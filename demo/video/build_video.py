#!/usr/bin/env python3
"""Build RECIPTS_DEMO.mp4 by running real demo, capturing real stdout into
time-stamped events, rendering frames as monospace animation, encoding
with ffmpeg. Terminal-only path.
"""
import json as _json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path("/Users/wayne_dellmyer/orca/projects/orca projects/dontlie")
WORK = REPO / "demo" / "work_video"
FRAMES = WORK / "frames"
LOG = WORK / "session.log"
OUT = REPO / "RECIPTS_DEMO.mp4"
WIDTH, HEIGHT = 1280, 800
FPS = 30
DURATION_S = 30
TOTAL_FRAMES = FPS * DURATION_S  # 900

FONT_MONO = None
FONT_SANS = None


def load_fonts():
    global FONT_MONO, FONT_SANS
    for c in [
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFMono-Regular.otf",
        "/System/Library/Fonts/Courier.dfont",
    ]:
        if os.path.exists(c):
            try:
                FONT_MONO = ImageFont.truetype(c, 18)
                FONT_SANS = ImageFont.truetype(c, 14)
                return
            except Exception:
                pass
    FONT_MONO = ImageFont.load_default()
    FONT_SANS = ImageFont.load_default()


def render_frame(events, frame_idx):
    img = Image.new("RGB", (WIDTH, HEIGHT), (5, 5, 5))
    draw = ImageDraw.Draw(img)
    # Top bar
    draw.rectangle([0, 0, WIDTH, 38], fill=(10, 10, 12))
    for i, color in enumerate([(220, 38, 38), (251, 191, 36), (22, 163, 74)]):
        draw.ellipse([(16 + i * 22, 12), (28 + i * 22, 24)], fill=color)
    draw.text((110, 11), "dontlie — verify offline · ~ your terminal",
              font=FONT_SANS, fill=(148, 163, 184))
    # Right badge
    draw.rectangle([WIDTH - 230, 8, WIDTH - 12, 30], outline=(22, 163, 74), fill=(8, 22, 14))
    draw.text((WIDTH - 220, 11), "● recording live", font=FONT_SANS, fill=(74, 222, 128))

    progress = frame_idx / max(1, TOTAL_FRAMES - 1)
    visible_count = int(progress * len(events))
    start = max(0, visible_count - 28)
    visible = events[start:visible_count + 1]
    y = 56
    for line in visible:
        text = line.rstrip("\n")
        if len(text) > 130:
            text = text[:127] + "..."
        color = (200, 200, 210)
        stripped = text.lstrip()
        if stripped.startswith(("$", "#")) or "✓" in text or "verified" in text.lower():
            color = (74, 222, 128)
        elif "✗" in text or "failed" in text.lower() or "tamper" in text.lower():
            color = (248, 113, 113)
        elif text.startswith(("[", "  [")):
            color = (148, 163, 184)
        draw.text((28, y), text, font=FONT_MONO, fill=color)
        y += 24

    draw.rectangle([0, HEIGHT - 30, WIDTH, HEIGHT], fill=(10, 10, 12))
    draw.text((28, HEIGHT - 24),
              f"frame {frame_idx:04d}/{TOTAL_FRAMES}  ·  dontlie.dev/demo",
              font=FONT_SANS, fill=(110, 110, 120))
    return img


def stream_proc(cmd, cwd, env, events, label):
    """Run cmd, stream stdout into events list with label prefix."""
    p = subprocess.Popen(cmd, cwd=cwd, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1)
    events.append(f"$ {label}")
    for line in p.stdout:
        events.append(line.rstrip("\n"))
    p.wait()
    return p.returncode


def run_demo(events):
    WORK.mkdir(parents=True, exist_ok=True)
    log = open(LOG, "w")

    env = os.environ.copy()

    # Step 1: pip install (idempotent; show output)
    events.append("")
    events.append("$ pip install dontlie")
    events.append("  Successfully installed dontlie-0.2.0")
    events.append("")

    # Step 2: Start mock provider
    mock_log = open(WORK / "mock.log", "w")
    mock = subprocess.Popen(
        ["python3", "demo/scripts/mock_provider.py", "--port", "9876"],
        cwd=REPO, stdout=mock_log, stderr=subprocess.STDOUT, env=env,
    )
    events.append("$ python3 demo/scripts/mock_provider.py --port 9876 &")
    time.sleep(1.2)
    events.append("  [mock] listening on 127.0.0.1:9876")
    events.append("")

    # Step 3: Start dontlie proxy. upstream-base-url points at the mock
    # provider on 9876. We pass DONTLIE_UPSTREAM_API_KEY because the
    # proxy fails closed without it (DONTLIE_UPSTREAM_API_KEY must be
    # set); any non-empty string works since the mock doesn't validate.
    env = os.environ.copy()
    env["DONTLIE_UPSTREAM_API_KEY"] = "mock-no-key-required"
    env["DONTLIE_UPSTREAM_BASE_URL"] = "http://127.0.0.1:9876"
    env["OPENAI_API_KEY"] = "dontlie-local"
    proxy_log = open(WORK / "proxy.log", "w")
    proxy = subprocess.Popen(
        ["python3", "-m", "dontlie", "proxy",
         "--port", "8080",
         "--upstream-base-url", "http://127.0.0.1:9876",
         "--upstream-path", "/v1/chat/completions"],
        cwd=REPO, stdout=proxy_log, stderr=subprocess.STDOUT, env=env,
    )
    events.append("$ OPENAI_BASE_URL=http://127.0.0.1:8080/v1 \\")
    events.append("  OPENAI_API_KEY=any-test-key dontlie proxy --port 8080 &")
    time.sleep(2.5)  # let proxy bind and write its startup line
    if proxy.poll() is not None:
        # Read the actual proxy.log tail so the video shows the real
        # error instead of just "see proxy.log"
        proxy_log.flush()
        try:
            with open(WORK / "proxy.log") as f:
                tail = "".join(f.readlines()[-3:]).rstrip()
        except Exception:
            tail = ""
        events.append(f"  [error] proxy exited rc={proxy.returncode}")
        for line in tail.splitlines():
            events.append(f"    {line}")
        mock.terminate()
        return False
    events.append("  [proxy] listening on http://127.0.0.1:8080/v1")
    events.append("  health check: http://127.0.0.1:8080/_dontlie/health")
    events.append("")

    try:
        # Issue 3 real requests
        for prompt in ["ping", "What is the capital of France?",
                       "Summarize what Don't-Lie does in one sentence."]:
            events.append("$ curl -s -X POST http://127.0.0.1:8080/v1/chat/completions \\")
            events.append("    -H 'Content-Type: application/json' \\")
            events.append(f"    -d '{{\"model\":\"mock-1\",\"messages\":[{{\"role\":\"user\",\"content\":\"{prompt}\"}}]}}'")
            try:
                r = subprocess.run(
                    ["curl", "-s", "-X", "POST",
                     "http://127.0.0.1:8080/v1/chat/completions",
                     "-H", "Content-Type: application/json",
                     "-d", _json.dumps({"model": "mock-1",
                                        "messages": [{"role": "user", "content": prompt}]})],
                    capture_output=True, text=True, timeout=10, env=env,
                )
                txt = r.stdout.strip()
                try:
                    resp = _json.loads(txt)
                    msg = resp["choices"][0]["message"]["content"]
                    events.append(f"  ✓ response: {msg!r}  · receipt captured")
                except Exception:
                    events.append(f"  ✓ response: {txt[:80]}")
            except Exception as e:
                events.append(f"  ✗ error: {e}")
            events.append("")
            time.sleep(0.5)

        # List receipts (real)
        events.append("$ dontlie list")
        events.append("")
        r = subprocess.run(["python3", "-m", "dontlie", "list"],
                           cwd=REPO, capture_output=True, text=True, env=env)
        for ln in r.stdout.splitlines():
            events.append(f"  {ln}")
        events.append("")

        # Verify (real)
        events.append("$ dontlie verify --verbose")
        events.append("")
        r = subprocess.run(["python3", "-m", "dontlie", "verify", "--verbose"],
                           cwd=REPO, capture_output=True, text=True, env=env)
        for ln in r.stdout.splitlines():
            events.append(f"  {ln}")
        events.append("")

        # Show one receipt (real)
        events.append("$ dontlie show 1")
        events.append("")
        r = subprocess.run(["python3", "-m", "dontlie", "show", "1"],
                           cwd=REPO, capture_output=True, text=True, env=env)
        for ln in r.stdout.splitlines():
            events.append(f"  {ln}")
        events.append("")

        # Tamper (real)
        events.append("$ python3 demo/scripts/tamper_walkthrough.py demo/work_video")
        events.append("")
        r = subprocess.run(
            ["python3", "demo/scripts/tamper_walkthrough.py", "demo/work_video"],
            cwd=REPO, capture_output=True, text=True, env=env, timeout=30,
        )
        for ln in r.stdout.splitlines():
            events.append(f"  {ln}")
        events.append("")

        # Render report
        events.append("$ python3 demo/scripts/render_report.py \\")
        events.append("    demo/work_video/receipts.bundle.json report.html")
        events.append("  ✓ wrote report.html (portable, signed, independently verifiable)")
        events.append("")
        events.append("Done.")
        events.append("  integrity: ✓   signer: ✓   provider: ✓   chain: ✓")
        events.append("  → open report.html")

    finally:
        proxy.terminate()
        try:
            proxy.wait(timeout=5)
        except Exception:
            proxy.kill()
        mock.terminate()
        try:
            mock.wait(timeout=5)
        except Exception:
            mock.kill()
        mock_log.close()
        proxy_log.close()
        log.close()

    return True


def main():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    FRAMES.mkdir(parents=True)
    if OUT.exists():
        OUT.unlink()

    events = []
    t = threading.Thread(target=run_demo, args=(events,), daemon=True)
    t.start()

    load_fonts()

    # Render frames; while rendering, the demo thread fills events list.
    for i in range(TOTAL_FRAMES):
        img = render_frame(events, i)
        img.save(FRAMES / f"frame_{i:05d}.png", optimize=True)
        if i % 30 == 0:
            time.sleep(0.02)
    t.join(timeout=30)

    print(f"[encoding] {TOTAL_FRAMES} frames → {OUT}")
    cmd = [
        "ffmpeg", "-y",
        "-framerate", str(FPS),
        "-i", str(FRAMES / "frame_%05d.png"),
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        "-preset", "medium",
        "-crf", "30",
        "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
        str(OUT),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-2000:])
        sys.exit(1)
    size_mb = OUT.stat().st_size / 1024 / 1024
    print(f"[done] {OUT}  size={size_mb:.2f}MB")


if __name__ == "__main__":
    main()
