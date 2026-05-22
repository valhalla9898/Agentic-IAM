"""Generate a demonstration video from attack simulation events.

This creates a video showing the attack timeline, useful when native
Playwright video recording is not available.
"""

from __future__ import annotations

import json

from moviepy import ColorClip, CompositeVideoClip, TextClip


def generate_demo_video(
    events_json: str, out_path: str, fps: int = 24, duration_per_event: float = 3.0
):
    """Generate a demo video showing attack events with timestamps.

    Args:
        events_json: Path to the JSON file containing events
        out_path: Output video file path
        fps: Frames per second
        duration_per_event: Duration to show each event (seconds)
    """
    with open(events_json, "r", encoding="utf-8") as fh:
        meta = json.load(fh)

    events = meta.get("events", [])
    if not events:
        print("No events to visualize")
        return

    # Create a base colored background clip
    duration = len(events) * duration_per_event
    bg = ColorClip(size=(1280, 720), color=(30, 30, 40))  # dark blue-gray
    bg = bg.with_duration(duration)

    clips = [bg]

    # Add title at the top
    title_txt = TextClip("Attack Simulation Log", fontsize=48, color="white", font="Arial")
    title_txt = title_txt.with_position(("center", 100)).with_duration(duration)
    clips.append(title_txt)

    # Add event timeline
    start_time = 0
    for i, event in enumerate(events):
        event_time = event.get("ts", "unknown")
        event_type = event.get("event", "unknown")

        # Build event details text
        details = []
        for key, val in event.items():
            if key not in ("ts", "event"):
                details.append(f"{key}: {val}")

        event_txt = f"[{i+1}] {event_type}\n{event_time}\n" + "\n".join(details)

        txt_clip = TextClip(
            event_txt,
            fontsize=24,
            color="#00FF00",
            font="Courier",
            method="caption",
            size=(1000, None),
        )
        txt_clip = (
            txt_clip.with_position(("center", "center"))
            .set_start(start_time)
            .with_duration(duration_per_event)
        )
        clips.append(txt_clip)

        start_time += duration_per_event

    # Compose and write
    final_video = CompositeVideoClip(clips)
    print(f"Writing demo video to {out_path}...")
    final_video.write_videofile(
        out_path, fps=fps, codec="libx264", audio=False, verbose=False, logger=None
    )
    print(f"Demo video created: {out_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python generate_demo_video.py <events.json> <output.mp4>")
        sys.exit(1)

    events_file = sys.argv[1]
    output_file = sys.argv[2]
    generate_demo_video(events_file, output_file)
