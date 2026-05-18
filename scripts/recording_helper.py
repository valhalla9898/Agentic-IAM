"""Helpers to post-process Playwright videos and annotate with events.

This uses `moviepy` to overlay simple timestamped annotations. If `ffmpeg`
is available on the system PATH, moviepy will use it.
"""
from __future__ import annotations
import json
import os
from moviepy.editor import VideoFileClip, TextClip, CompositeVideoClip


def annotate_video(video_path: str, events_json: str, out_path: str):
    with open(events_json, 'r', encoding='utf-8') as fh:
        meta = json.load(fh)
    events = meta.get('events', [])

    clip = VideoFileClip(video_path)
    txt_clips = []
    # Very simple: show last event text at bottom for 3s each in sequence
    start = 0
    for ev in events:
        txt = f"{ev.get('ts')} - {ev.get('event')}"
        txt_clip = (TextClip(txt, fontsize=24, color='white')
                    .set_position(('center', 'bottom'))
                    .set_start(start)
                    .set_duration(3))
        txt_clips.append(txt_clip)
        start += 3

    final = CompositeVideoClip([clip, *txt_clips])
    final.write_videofile(out_path, codec='libx264')
