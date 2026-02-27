from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
MERGE_UPLOAD_DIR = BASE_DIR / "merge_uploads"
MERGE_OUTPUT_DIR = BASE_DIR / "merge_clips"
MERGE_MEMORY_FILE = BASE_DIR / "merge_memory_store.json"
MAX_MERGE_SOURCE_PAIRS = 2
DEFAULT_FFMPEG_EXE = Path(
    r"C:\Users\ANIRBAN SINHA\AppData\Local\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.0.1-full_build\bin\ffmpeg.exe"
)
DEFAULT_FFPROBE_EXE = DEFAULT_FFMPEG_EXE.with_name("ffprobe.exe")

for directory in (MERGE_UPLOAD_DIR, MERGE_OUTPUT_DIR):
    directory.mkdir(parents=True, exist_ok=True)

if not MERGE_MEMORY_FILE.exists():
    MERGE_MEMORY_FILE.write_text(json.dumps({"sources": []}, indent=2), encoding="utf-8")

MERGE_JOBS: dict[str, dict] = {}
MERGE_LOCK = threading.Lock()
MERGE_MEMORY_LOCK = threading.Lock()
BINARIES_LOCK = threading.Lock()
BINARIES_CACHE: dict[str, str] | None = None

router = APIRouter(prefix="/api/merge", tags=["video_merge"])


def _resolve_binaries() -> dict[str, str]:
    global BINARIES_CACHE
    with BINARIES_LOCK:
        if BINARIES_CACHE is not None:
            return BINARIES_CACHE

        ffmpeg_path = str(DEFAULT_FFMPEG_EXE) if DEFAULT_FFMPEG_EXE.exists() else shutil.which("ffmpeg")
        ffprobe_path = str(DEFAULT_FFPROBE_EXE) if DEFAULT_FFPROBE_EXE.exists() else shutil.which("ffprobe")
        if not ffmpeg_path or not ffprobe_path:
            raise RuntimeError("FFmpeg/FFprobe not found. Ensure they are installed and in PATH.")

        BINARIES_CACHE = {"ffmpeg": ffmpeg_path, "ffprobe": ffprobe_path}
        return BINARIES_CACHE


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    if not cmd:
        raise RuntimeError("Empty command.")
    bins = _resolve_binaries()
    tool = cmd[0].lower()
    if tool in bins:
        cmd = [bins[tool], *cmd[1:]]
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError("FFmpeg/FFprobe not found. Ensure they are installed and in PATH.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError((exc.stderr or "").strip() or "Command execution failed.") from exc


def _probe_duration_seconds(path: Path) -> float:
    out = _run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            str(path),
        ]
    ).stdout.strip()
    try:
        val = float(out)
    except ValueError as exc:
        raise RuntimeError("Unable to read valid video duration.") from exc
    if val <= 0:
        raise RuntimeError("Unable to read valid video duration.")
    return val


def _probe_has_audio(path: Path) -> bool:
    out = _run(
        [
            "ffprobe",
            "-v",
            "error",
            "-select_streams",
            "a",
            "-show_entries",
            "stream=index",
            "-of",
            "csv=p=0",
            str(path),
        ]
    ).stdout.strip()
    return bool(out)


def _escape_text(text: str) -> str:
    escaped = text.replace("\\", "\\\\")
    escaped = escaped.replace(":", r"\:")
    escaped = escaped.replace("'", r"\'")
    escaped = escaped.replace("%", r"\%")
    return escaped


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(v)))


def _validate_settings(raw: dict) -> dict:
    def safe_rect(raw_rect: dict, defaults: tuple[int, int, int, int]) -> dict:
        x, y, w, h = defaults
        if isinstance(raw_rect, dict):
            x = _clamp(raw_rect.get("x", x), 0, 1080)
            y = _clamp(raw_rect.get("y", y), 0, 1920)
            w = _clamp(raw_rect.get("w", w), 120, 1080)
            h = _clamp(raw_rect.get("h", h), 120, 1920)
        return {"x": x, "y": y, "w": w, "h": h}

    video1 = safe_rect(raw.get("video1", {}), (0, 0, 1080, 960))
    video2 = safe_rect(raw.get("video2", {}), (0, 960, 1080, 960))

    audio1 = _clamp(raw.get("audio1_pct", 100), 0, 100)
    audio2 = _clamp(raw.get("audio2_pct", 0), 0, 100)

    default_color = "#FFFFFF"
    texts: list[dict] = []
    raw_texts = raw.get("texts", [])
    if isinstance(raw_texts, list):
        for item in raw_texts[:20]:
            if not isinstance(item, dict):
                continue
            txt = str(item.get("text", "")).strip()[:160]
            if not txt:
                continue
            color = str(item.get("color", default_color)).strip()
            if not re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
                color = default_color
            size = _clamp(item.get("size", 48), 16, 120)
            x = _clamp(item.get("x", 40), 0, 1080)
            y = _clamp(item.get("y", 60), 0, 1920)
            texts.append({"text": txt, "color": color, "size": size, "x": x, "y": y})

    return {"video1": video1, "video2": video2, "audio1_pct": audio1, "audio2_pct": audio2, "texts": texts}


def _read_merge_memory() -> dict:
    with MERGE_MEMORY_LOCK:
        try:
            return json.loads(MERGE_MEMORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {"sources": []}


def _write_merge_memory(data: dict) -> None:
    with MERGE_MEMORY_LOCK:
        MERGE_MEMORY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _serialize_source(source: dict) -> dict:
    return {
        "id": source.get("id"),
        "video1_name": source.get("video1_name"),
        "video2_name": source.get("video2_name"),
        "video1_duration_sec": source.get("video1_duration_sec"),
        "video2_duration_sec": source.get("video2_duration_sec"),
        "created_at": source.get("created_at"),
        "results_count": len(source.get("results", []) or []),
        "results": source.get("results", []),
    }


def _find_source(source_id: str) -> dict | None:
    memory = _read_merge_memory()
    return next((s for s in memory.get("sources", []) if s.get("id") == source_id), None)


def _build_filter_complex(settings: dict, has_a1: bool, has_a2: bool) -> tuple[str, bool]:
    v1 = settings["video1"]
    v2 = settings["video2"]

    filters = [
        f"[0:v]scale={v1['w']}:{v1['h']}:flags=fast_bilinear[v0]",
        f"[1:v]scale={v2['w']}:{v2['h']}:flags=fast_bilinear[v1]",
        "color=c=black:s=1080x1920[base]",
        f"[base][v0]overlay={v1['x']}:{v1['y']}[tmp1]",
        f"[tmp1][v1]overlay={v2['x']}:{v2['y']}[vtxt0]",
    ]

    prev = "vtxt0"
    for idx, text_item in enumerate(settings["texts"], start=1):
        color = str(text_item["color"]).replace("#", "0x")
        nxt = f"vtxt{idx}"
        filters.append(
            f"[{prev}]drawtext=text='{_escape_text(text_item['text'])}':font='Arial':fontcolor={color}:fontsize={int(text_item['size'])}:x={int(text_item['x'])}:y={int(text_item['y'])}[{nxt}]"
        )
        prev = nxt
    filters.append(f"[{prev}]null[vout]")

    has_audio_out = False
    a1 = settings["audio1_pct"] / 100.0
    a2 = settings["audio2_pct"] / 100.0
    if has_a1 and has_a2:
        filters.append(f"[0:a]volume={a1:.2f}[a0]")
        filters.append(f"[1:a]volume={a2:.2f}[a1]")
        filters.append("[a0][a1]amix=inputs=2:duration=shortest[aout]")
        has_audio_out = True
    elif has_a1:
        filters.append(f"[0:a]volume={a1:.2f}[aout]")
        has_audio_out = True
    elif has_a2:
        filters.append(f"[1:a]volume={a2:.2f}[aout]")
        has_audio_out = True

    return ";".join(filters), has_audio_out


def _serialize_job(job: dict) -> dict:
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "progress": job.get("progress", 0.0),
        "error": job.get("error"),
        "output_url": job.get("output_url"),
        "output_name": job.get("output_name"),
        "cancel_requested": bool(job.get("cancel_requested", False)),
    }


def _process_merge_job(job_id: str, source_id: str, input1: Path, input2: Path, settings: dict) -> None:
    with MERGE_LOCK:
        job = MERGE_JOBS[job_id]
        job["status"] = "processing"
        job["progress"] = 0.0

    output_name = f"merged_{job_id[:8]}.mp4"
    output_path = MERGE_OUTPUT_DIR / output_name

    try:
        d1 = _probe_duration_seconds(input1)
        d2 = _probe_duration_seconds(input2)
        duration = max(1.0, min(d1, d2))
        has_a1 = _probe_has_audio(input1)
        has_a2 = _probe_has_audio(input2)
        filter_complex, has_audio_out = _build_filter_complex(settings, has_a1, has_a2)

        cmd = [
            "ffmpeg",
            "-y",
            "-i",
            str(input1),
            "-i",
            str(input2),
            "-t",
            f"{duration:.3f}",
            "-filter_complex",
            filter_complex,
            "-map",
            "[vout]",
        ]
        if has_audio_out:
            cmd += ["-map", "[aout]", "-c:a", "aac", "-b:a", "160k"]
        else:
            cmd += ["-an"]
        cmd += [
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-crf",
            "23",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            "-progress",
            "pipe:1",
            "-nostats",
            str(output_path),
        ]

        bins = _resolve_binaries()
        cmd[0] = bins["ffmpeg"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        log_tail: list[str] = []
        with MERGE_LOCK:
            if job_id in MERGE_JOBS:
                MERGE_JOBS[job_id]["process"] = proc

        if proc.stdout is not None:
            for line in proc.stdout:
                row = line.strip()
                if row:
                    log_tail.append(row)
                    if len(log_tail) > 80:
                        log_tail.pop(0)
                with MERGE_LOCK:
                    cancel_requested = bool(MERGE_JOBS.get(job_id, {}).get("cancel_requested", False))
                if cancel_requested and proc.poll() is None:
                    proc.terminate()
                if row.startswith("out_time_ms="):
                    try:
                        out_ms = int(row.split("=", 1)[1])
                    except ValueError:
                        out_ms = 0
                    pct = max(0.0, min(99.0, (out_ms / (duration * 1_000_000.0)) * 100.0))
                    with MERGE_LOCK:
                        if job_id in MERGE_JOBS:
                            MERGE_JOBS[job_id]["progress"] = round(pct, 2)

        rc = proc.wait()
        with MERGE_LOCK:
            cancel_requested = bool(MERGE_JOBS.get(job_id, {}).get("cancel_requested", False))
            if job_id in MERGE_JOBS:
                MERGE_JOBS[job_id]["process"] = None

        if cancel_requested:
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
            with MERGE_LOCK:
                if job_id in MERGE_JOBS:
                    MERGE_JOBS[job_id]["status"] = "cancelled"
                    MERGE_JOBS[job_id]["progress"] = 0.0
            return

        if rc != 0:
            tail = "\n".join(log_tail[-12:]).strip()
            raise RuntimeError(tail or "FFmpeg merge failed.")

        with MERGE_LOCK:
            if job_id in MERGE_JOBS:
                MERGE_JOBS[job_id]["status"] = "completed"
                MERGE_JOBS[job_id]["progress"] = 100.0
                MERGE_JOBS[job_id]["output_name"] = output_name
                MERGE_JOBS[job_id]["output_url"] = f"/merge_clips/{output_name}"

        memory = _read_merge_memory()
        for src in memory.get("sources", []):
            if src.get("id") == source_id:
                results = src.setdefault("results", [])
                results.append(
                    {
                        "name": output_name,
                        "url": f"/merge_clips/{output_name}",
                        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                    }
                )
                break
        _write_merge_memory(memory)
    except Exception as exc:
        with MERGE_LOCK:
            if job_id in MERGE_JOBS:
                MERGE_JOBS[job_id]["status"] = "failed"
                MERGE_JOBS[job_id]["error"] = str(exc)


@router.post("/process")
async def process_merge(
    video1: UploadFile | None = File(None),
    video2: UploadFile | None = File(None),
    settings_json: str = Form("{}"),
    source_id: str = Form(""),
) -> JSONResponse:
    try:
        raw_settings = json.loads(settings_json or "{}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid settings payload.")
    settings = _validate_settings(raw_settings if isinstance(raw_settings, dict) else {})

    selected_source_id = str(source_id or "").strip()
    in1: Path
    in2: Path

    if selected_source_id:
        source = _find_source(selected_source_id)
        if source is None:
            raise HTTPException(status_code=404, detail="Merge memory source not found.")
        in1 = Path(str(source.get("video1_path", "")))
        in2 = Path(str(source.get("video2_path", "")))
        if not in1.exists() or not in2.exists():
            raise HTTPException(status_code=404, detail="Stored source files are missing. Delete this record and re-upload.")
    else:
        if video1 is None or video2 is None or not video1.filename or not video2.filename:
            raise HTTPException(status_code=400, detail="Please select both video files.")

        memory = _read_merge_memory()
        sources = memory.get("sources", [])
        if len(sources) >= MAX_MERGE_SOURCE_PAIRS:
            raise HTTPException(
                status_code=409,
                detail="Merge memory full: delete one stored pair before uploading new videos.",
            )

        new_source_id = uuid.uuid4().hex
        safe1 = Path(video1.filename).name
        safe2 = Path(video2.filename).name
        in1 = MERGE_UPLOAD_DIR / f"{new_source_id}_1_{safe1}"
        in2 = MERGE_UPLOAD_DIR / f"{new_source_id}_2_{safe2}"

        try:
            with in1.open("wb") as f1:
                shutil.copyfileobj(video1.file, f1)
            with in2.open("wb") as f2:
                shutil.copyfileobj(video2.file, f2)
        finally:
            try:
                video1.file.close()
            except Exception:
                pass
            try:
                video2.file.close()
            except Exception:
                pass

        d1 = _probe_duration_seconds(in1)
        d2 = _probe_duration_seconds(in2)
        sources.append(
            {
                "id": new_source_id,
                "video1_name": safe1,
                "video2_name": safe2,
                "video1_path": str(in1),
                "video2_path": str(in2),
                "video1_duration_sec": round(d1, 3),
                "video2_duration_sec": round(d2, 3),
                "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "results": [],
            }
        )
        memory["sources"] = sources
        _write_merge_memory(memory)
        selected_source_id = new_source_id

    with MERGE_LOCK:
        job_id = uuid.uuid4().hex
        MERGE_JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "progress": 0.0,
            "error": None,
            "output_url": None,
            "source_id": selected_source_id,
            "cancel_requested": False,
            "process": None,
        }

    worker = threading.Thread(target=_process_merge_job, args=(job_id, selected_source_id, in1, in2, settings), daemon=True)
    worker.start()

    return JSONResponse({"job_id": job_id, "source_id": selected_source_id})


@router.get("/sources")
async def list_merge_sources() -> JSONResponse:
    memory = _read_merge_memory()
    sources = [_serialize_source(s) for s in memory.get("sources", [])]
    return JSONResponse(
        {
            "sources": sources,
            "capacity_pairs": MAX_MERGE_SOURCE_PAIRS,
            "capacity_videos": MAX_MERGE_SOURCE_PAIRS * 2,
            "used_pairs": len(sources),
            "used_videos": len(sources) * 2,
        }
    )


@router.delete("/source/{source_id}")
async def delete_merge_source(source_id: str) -> JSONResponse:
    memory = _read_merge_memory()
    sources = memory.get("sources", [])
    idx = next((i for i, s in enumerate(sources) if s.get("id") == source_id), None)
    if idx is None:
        raise HTTPException(status_code=404, detail="Merge memory source not found.")
    src = sources.pop(idx)
    memory["sources"] = sources
    _write_merge_memory(memory)

    p1 = Path(str(src.get("video1_path", "")))
    p2 = Path(str(src.get("video2_path", "")))
    try:
        p1.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        p2.unlink(missing_ok=True)
    except OSError:
        pass

    return JSONResponse({"deleted": source_id})


@router.get("/job/{job_id}")
async def get_merge_job(job_id: str) -> JSONResponse:
    with MERGE_LOCK:
        job = MERGE_JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Merge job not found.")
        return JSONResponse(_serialize_job(job))


@router.post("/cancel/{job_id}")
async def cancel_merge_job(job_id: str) -> JSONResponse:
    with MERGE_LOCK:
        job = MERGE_JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Merge job not found.")
        if job.get("status") not in {"queued", "processing"}:
            return JSONResponse({"job_id": job_id, "status": job.get("status")})
        job["cancel_requested"] = True
        proc = job.get("process")
    try:
        if proc is not None and proc.poll() is None:
            proc.terminate()
    except Exception:
        pass
    return JSONResponse({"job_id": job_id, "status": "cancelling"})


def install_merge_tool(app: FastAPI) -> None:
    if not any(getattr(route, "path", "") == "/merge_clips" for route in app.router.routes):
        app.mount("/merge_clips", StaticFiles(directory=str(MERGE_OUTPUT_DIR)), name="merge_clips")
    app.include_router(router)
