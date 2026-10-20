from pathlib import Path
import math
import struct
import wave

# Original, synthesized cues. No third-party samples are used.
ROOT = Path(__file__).resolve().parent.parent / "assets"
ROOT.mkdir(exist_ok=True)
RATE = 44100
for name, notes in (("开麦.wav", (392.0, 523.25)), ("关麦.wav", (523.25, 349.23))):
    frames = []
    for index, frequency in enumerate(notes):
        duration = 0.14 if index == 0 else 0.22
        for sample in range(round(duration * RATE)):
            t = sample / RATE
            attack = min(1.0, t / 0.012)
            release = min(1.0, (duration - t) / 0.035)
            envelope = attack * release * math.exp(-t * 7)
            tone = math.sin(2 * math.pi * frequency * t)
            tone += 0.12 * math.sin(2 * math.pi * frequency * 2 * t)
            frames.append(struct.pack("<h", round(12500 * envelope * tone)))
        frames.extend([b"\0\0"] * round(RATE * 0.018))
    with wave.open(str(ROOT / name), "wb") as output:
        output.setparams((1, 2, RATE, 0, "NONE", "not compressed"))
        output.writeframes(b"".join(frames))
