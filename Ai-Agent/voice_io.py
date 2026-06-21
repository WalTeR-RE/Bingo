"""
voice_io.py — low-latency microphone capture for the Bingo behavioral agent.

VoiceListener keeps a single PyAudio input stream open for the whole session
and uses webrtcvad to detect when the user starts and stops talking, so a turn
ends naturally on silence instead of on a fixed timer. The user can pause to
think without being cut off, and the mic is never closed between turns, so
nothing said right after Bingo finishes is missed.

Captured utterances are 16 kHz, mono, 16-bit little-endian PCM bytes — the
exact format the existing transcription path already expects — and are handed
off through a thread-safe queue.

The module is import-safe: if PyAudio or webrtcvad are missing, or the input
device cannot be opened, VoiceListener.available stays False and the caller
should fall back to the legacy fixed-window recorder.
"""

import contextlib
import ctypes
import faulthandler
import os
import queue
import threading

try:
    import webrtcvad
    import pyaudio
    _DEPS_OK = True
except Exception:
    _DEPS_OK = False


def init_thread_com():
    """Join the COM multithreaded apartment on the current thread.

    PortAudio's WASAPI backend uses COM; when PyAudio is created or used on a
    thread that never initialized COM (as with Qt worker threads), Windows
    raises apartment errors such as 0x8001010d. Joining the MTA on every audio
    thread makes those calls valid and lets the streams be shared safely across
    the worker threads. Repeat calls, or calls on a thread already in an
    apartment, are harmless and ignored.
    """
    if os.name != "nt":
        return
    try:
        ctypes.windll.ole32.CoInitializeEx(None, 0x0)
    except Exception:
        pass


@contextlib.contextmanager
def _quiet_faulthandler():
    """Silence faulthandler's first-chance 'Windows fatal exception' dump around
    a call known to raise-and-handle a benign SEH internally.

    PortAudio's WASAPI backend raises a COM exception (0x8001010d) during
    Pa_Initialize that it catches and recovers from, but faulthandler's Windows
    vectored handler still prints it, which looks like a crash even though the
    audio device opens normally. We disable faulthandler only for the duration
    of the device call, then restore it so genuine crashes are still reported.
    """
    was_enabled = faulthandler.is_enabled()
    if was_enabled:
        faulthandler.disable()
    try:
        yield
    finally:
        if was_enabled:
            faulthandler.enable()


SAMPLE_RATE = 16000
SAMPLE_WIDTH = 2
CHANNELS = 1
FRAME_MS = 30
FRAME_SAMPLES = int(SAMPLE_RATE * FRAME_MS / 1000)
FRAME_BYTES = FRAME_SAMPLES * SAMPLE_WIDTH


def _env_int(name, default):
    """Read an integer environment override, falling back to default on error."""
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class VoiceListener:
    """Continuous VAD-based microphone listener.

    Call start() once. Pull finished utterances with get_utterance(). Suspend
    capture while the agent is speaking or processing a turn with
    pause()/resume() — these are reference-counted so nested pause/resume pairs
    (for example, a turn that also speaks) balance correctly.
    """

    def __init__(self):
        self.available = False
        self._pa = None
        self._stream = None
        self._vad = None
        self._thread = None
        self._stop = threading.Event()
        self._utterances = queue.Queue()
        self._pause_count = 0
        self._pause_lock = threading.Lock()

        self._aggr = max(0, min(3, _env_int("BINGO_VAD_AGGRESSIVENESS", 2)))
        eos_ms = _env_int("BINGO_EOS_SILENCE_MS", 700)
        onset_ms = _env_int("BINGO_VAD_ONSET_MS", 200)
        max_s = _env_int("BINGO_MAX_UTTERANCE_S", 30)
        self._eos_frames = max(1, eos_ms // FRAME_MS)
        self._onset_frames = max(1, onset_ms // FRAME_MS)
        self._max_frames = max(self._onset_frames + 1, int(max_s * 1000 / FRAME_MS))

        if not _DEPS_OK:
            return
        try:
            init_thread_com()
            self._vad = webrtcvad.Vad(self._aggr)
            with _quiet_faulthandler():
                self._pa = pyaudio.PyAudio()
                self._stream = self._pa.open(
                    format=pyaudio.paInt16,
                    channels=CHANNELS,
                    rate=SAMPLE_RATE,
                    input=True,
                    frames_per_buffer=FRAME_SAMPLES,
                )
            self.available = True
        except Exception:
            self._cleanup()
            self.available = False

    def start(self):
        """Begin the background capture loop. No-op if unavailable or started."""
        if not self.available or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def pause(self):
        """Suspend capture (reference-counted, safe to nest)."""
        with self._pause_lock:
            self._pause_count += 1

    def resume(self):
        """Undo one pause(); capture resumes once all pauses are undone."""
        with self._pause_lock:
            if self._pause_count > 0:
                self._pause_count -= 1

    @property
    def _listening(self):
        with self._pause_lock:
            return self._pause_count == 0

    def get_utterance(self, timeout=0.5):
        """Return the next captured utterance (PCM bytes), or None on timeout."""
        try:
            return self._utterances.get(timeout=timeout)
        except queue.Empty:
            return None

    def clear(self):
        """Drop any buffered utterances (e.g. echo captured while Bingo spoke)."""
        try:
            while True:
                self._utterances.get_nowait()
        except queue.Empty:
            pass

    def stop(self):
        """Stop the capture loop and release the audio device."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self._cleanup()

    def _run(self):
        """Read 30 ms frames continuously; run VAD endpointing while listening.

        While paused, frames are still read and discarded so the device buffer
        stays drained and the agent never transcribes its own voice or stale
        audio. The endpointer keeps a short pre-roll so the first word of a turn
        is not clipped, and ends the turn after a run of silence.
        """
        init_thread_com()
        voiced = []
        triggered = False
        silence_run = 0
        onset_ring = []
        while not self._stop.is_set():
            try:
                frame = self._stream.read(FRAME_SAMPLES, exception_on_overflow=False)
            except Exception:
                continue
            if len(frame) < FRAME_BYTES:
                continue
            if not self._listening:
                voiced, triggered, silence_run, onset_ring = [], False, 0, []
                continue
            try:
                speech = self._vad.is_speech(frame, SAMPLE_RATE)
            except Exception:
                continue
            if not triggered:
                onset_ring.append((frame, speech))
                if len(onset_ring) > self._onset_frames:
                    onset_ring.pop(0)
                if sum(1 for _, s in onset_ring if s) > 0.9 * self._onset_frames:
                    triggered = True
                    voiced = [f for f, _ in onset_ring]
                    onset_ring = []
                    silence_run = 0
            else:
                voiced.append(frame)
                silence_run = 0 if speech else silence_run + 1
                if silence_run >= self._eos_frames or len(voiced) >= self._max_frames:
                    self._utterances.put(b"".join(voiced))
                    voiced, triggered, silence_run = [], False, 0

    def _cleanup(self):
        """Best-effort release of the stream and PyAudio instance."""
        try:
            if self._stream is not None:
                self._stream.stop_stream()
                self._stream.close()
        except Exception:
            pass
        try:
            if self._pa is not None:
                self._pa.terminate()
        except Exception:
            pass
        self._stream = None
        self._pa = None


def split_sentences(buffer, min_len=16):
    """Pull complete sentences off the front of a streaming text buffer.

    Returns (sentences, remainder). A sentence is flushed when a run of
    sentence-ending punctuation is reached and the accumulated text is at least
    min_len characters — this avoids emitting tiny fragments or splitting on
    decimals/abbreviations, while still starting playback quickly.
    """
    sentences = []
    start = 0
    i = 0
    n = len(buffer)
    while i < n:
        if buffer[i] in ".!?\n":
            j = i
            while j + 1 < n and buffer[j + 1] in ".!?\n":
                j += 1
            candidate = buffer[start:j + 1].strip()
            if len(candidate) >= min_len:
                sentences.append(candidate)
                start = j + 1
                i = j + 1
                continue
            i = j + 1
        else:
            i += 1
    return sentences, buffer[start:]


class StreamingSpeaker:
    """Plays OpenAI TTS audio as it streams, sentence by sentence.

    Each sentence's PCM is written to a PyAudio output stream as it arrives, so
    the first audio starts as soon as the first sentence is ready instead of
    after the whole reply is synthesized. Import-safe: if PyAudio is missing or
    no output device opens, available stays False and the caller should fall
    back to the buffered tts-1 + pygame path.
    """

    OUTPUT_RATE = 24000

    def __init__(self, openai_client, model="tts-1", voice="alloy"):
        self.available = False
        self._client = openai_client
        self._model = model
        self._voice = voice
        self._pa = None
        self._stream = None
        self._interrupt = threading.Event()
        try:
            self._timeout = float(os.environ.get("BINGO_TTS_TIMEOUT", "15"))
        except (TypeError, ValueError):
            self._timeout = 15.0
        if not _DEPS_OK:
            return
        try:
            init_thread_com()
            with _quiet_faulthandler():
                self._pa = pyaudio.PyAudio()
                self._stream = self._pa.open(
                    format=pyaudio.paInt16,
                    channels=1,
                    rate=self.OUTPUT_RATE,
                    output=True,
                )
            self.available = True
        except Exception:
            self._cleanup()
            self.available = False

    def interrupt(self):
        """Request that the current playback stop as soon as possible."""
        self._interrupt.set()

    def play_sentences(self, sentences, on_start=None, on_done=None, on_sentence=None):
        """Synthesize and play an iterable of text sentences in order.

        on_start fires once before the first audio, on_sentence(text) fires per
        sentence (for live captions), on_done fires when finished. Returns the
        full text actually spoken.
        """
        self._interrupt.clear()
        started = False
        spoken = []
        try:
            for sentence in sentences:
                s = (sentence or "").strip()
                if not s:
                    continue
                if self._interrupt.is_set():
                    break
                if not started:
                    if on_start:
                        on_start()
                    started = True
                if on_sentence:
                    on_sentence(s)
                spoken.append(s)
                try:
                    self._speak_one(s)
                except Exception:
                    self._reset_stream()
                    continue
                if self._interrupt.is_set():
                    break
        finally:
            if started and on_done:
                on_done()
        return " ".join(spoken)

    def _speak_one(self, text):
        """Stream one sentence's PCM from the TTS API straight to the speaker."""
        kwargs = dict(
            model=self._model,
            voice=self._voice,
            input=text,
            response_format="pcm",
        )
        if self._model.startswith("tts-1"):
            kwargs["speed"] = 1.15
        client = self._client.with_options(timeout=self._timeout)
        with client.audio.speech.with_streaming_response.create(**kwargs) as response:
            for chunk in response.iter_bytes(chunk_size=4096):
                if self._interrupt.is_set():
                    break
                if chunk:
                    self._stream.write(chunk)

    def _reset_stream(self):
        """Reopen the output stream after a failed sentence.

        A timed-out or aborted TTS request can leave the PyAudio output stream
        in a partially written state. Closing and reopening it gives the next
        sentence a clean stream so one stalled sentence cannot mute or wedge the
        rest of the reply. Best-effort: on failure the speaker is marked
        unavailable so the caller falls back to the buffered path.
        """
        if not _DEPS_OK or self._pa is None:
            return
        try:
            if self._stream is not None:
                with contextlib.suppress(Exception):
                    self._stream.stop_stream()
                with contextlib.suppress(Exception):
                    self._stream.close()
            with _quiet_faulthandler():
                self._stream = self._pa.open(
                    format=pyaudio.paInt16,
                    channels=1,
                    rate=self.OUTPUT_RATE,
                    output=True,
                )
        except Exception:
            self._stream = None
            self.available = False

    def stop(self):
        """Release the output stream and PyAudio instance."""
        self._cleanup()

    def _cleanup(self):
        """Best-effort release of the output stream and PyAudio instance."""
        try:
            if self._stream is not None:
                self._stream.stop_stream()
                self._stream.close()
        except Exception:
            pass
        try:
            if self._pa is not None:
                self._pa.terminate()
        except Exception:
            pass
        self._stream = None
        self._pa = None
