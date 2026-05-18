"""Generate a demonstration video from attack simulation events.

This creates a video showing the attack timeline using PIL + imageio,
avoiding moviepy version compatibility issues.
"""
from __future__ import annotations
import json
import os
from PIL import Image, ImageDraw, ImageFont
import imageio


def generate_demo_video(events_json: str, out_path: str, fps: int = 1, duration_per_event: int = 3):
    """Generate a demo video showing attack events with timestamps.
    
    Args:
        events_json: Path to the JSON file containing events
        out_path: Output video file path
        fps: Frames per second
        duration_per_event: Duration to show each event (seconds)
    """
    with open(events_json, 'r', encoding='utf-8') as fh:
        meta = json.load(fh)
    
    events = meta.get('events', [])
    if not events:
        print("No events to visualize")
        return
    
    # Create frames for the video
    frames = []
    width, height = 1280, 720
    
    # Add event timeline
    for i, event in enumerate(events):
        # Create a new image for this event
        img = Image.new('RGB', (width, height), color=(30, 30, 40))
        draw = ImageDraw.Draw(img)
        
        # Try to load a decent font, fall back to default
        try:
            title_font = ImageFont.truetype("arial.ttf", 48)
            event_font = ImageFont.truetype("courier.ttf", 24)
        except OSError:
            title_font = ImageFont.load_default()
            event_font = ImageFont.load_default()
        
        # Draw title
        draw.text((100, 50), "Attack Simulation Log", fill=(255, 255, 255), font=title_font)
        
        # Draw event number
        draw.text((100, 150), f"Event {i+1} / {len(events)}", fill=(0, 255, 0), font=event_font)
        
        # Draw event type
        event_type = event.get('event', 'unknown')
        draw.text((100, 200), f"Type: {event_type}", fill=(0, 255, 0), font=event_font)
        
        # Draw timestamp
        event_ts = event.get('ts', 'unknown')
        draw.text((100, 250), f"Time: {event_ts}", fill=(0, 255, 0), font=event_font)
        
        # Draw additional details
        y_offset = 320
        for key, val in event.items():
            if key not in ('ts', 'event'):
                detail_txt = f"{key}: {val}"
                draw.text((100, y_offset), detail_txt, fill=(200, 200, 200), font=event_font)
                y_offset += 50
        
        # Add frame repeated for duration_per_event seconds
        frame_array = None
        try:
            import numpy as np
            frame_array = np.array(img)
        except ImportError:
            # Fallback: just save the PIL image
            pass
        
        if frame_array is not None:
            for _ in range(fps * duration_per_event):
                frames.append(frame_array)
    
    # Write video using imageio
    if frames:
        print(f"Writing demo video to {out_path}...")
        imageio.mimsave(out_path, frames, fps=fps, codec='libx264')
        print(f"Demo video created: {out_path}")
    else:
        print("No frames generated")


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print("Usage: python generate_demo_video.py <events.json> <output.mp4>")
        sys.exit(1)
    
    events_file = sys.argv[1]
    output_file = sys.argv[2]
    generate_demo_video(events_file, output_file)
