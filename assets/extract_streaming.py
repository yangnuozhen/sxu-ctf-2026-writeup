#!/usr/bin/env python3
"""Streaming 第一阶段复现：RTP/H.264 重组及未知附件统计。

需要 PATH 中的 tshark。只输出 Annex-B 视频流、TSV 和 JSON.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import subprocess

BUNDLE = Path(__file__).resolve().parents[1]
START_CODE = b"\x00\x00\x00\x01"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def extract(capture, output):
    fields = ["frame.number", "ip.src", "udp.srcport", "ip.dst", "udp.dstport",
              "rtp.ssrc", "rtp.p_type", "rtp.seq", "rtp.timestamp",
              "rtp.marker", "rtp.payload"]
    command = ["tshark", "-r", str(capture), "-d", "udp.port==1234,rtp",
               "-Y", "rtp", "-T", "fields"]
    for field in fields:
        command.extend(["-e", field])
    rows = subprocess.check_output(command, text=True)
    (output / "01_rtp.tsv").write_text("\t".join(fields) + "\n" + rows,
                                        encoding="utf-8")
    video = bytearray()
    packet_types = Counter()
    nal_types = Counter()
    flows = set()
    timestamps = set()
    sequences = []
    markers = 0
    fragment = None
    fragment_header = None
    fragment_timestamp = None

    def emit(nal):
        if not nal or not 1 <= (nal[0] & 31) <= 23:
            raise ValueError("Invalid reconstructed NAL unit")
        video.extend(START_CODE + nal)
        nal_types[nal[0] & 31] += 1

    for line in rows.splitlines():
        frame, src, sport, dst, dport, ssrc, pt, seq, timestamp, marker, payload = line.split("\t")
        sequence = int(seq)
        if sequences and sequence != (sequences[-1] + 1) % 65536:
            raise ValueError(f"Missing/out-of-order RTP sequence at frame {frame}")
        sequences.append(sequence)
        flows.add((src, sport, dst, dport, ssrc, pt))
        if len(flows) != 1:
            raise ValueError("Multiple RTP flows: select one flow before reassembly")
        timestamps.add(int(timestamp))
        markers += int(marker.lower() in ("1", "true"))
        data = bytes.fromhex(payload.replace(":", ""))
        if not data:
            raise ValueError(f"Empty RTP payload at frame {frame}")
        kind = data[0] & 31
        packet_types[kind] += 1
        if kind != 28 and fragment is not None:
            raise ValueError("Incomplete FU-A before another NAL unit")
        if 1 <= kind <= 23:
            emit(data)
        elif kind == 24:  # STAP-A: indicator + repeated (uint16 length, NAL).
            position = 1
            while position < len(data):
                if position + 2 > len(data):
                    raise ValueError("Truncated STAP-A length")
                size = int.from_bytes(data[position:position + 2], "big")
                position += 2
                if size == 0 or position + size > len(data):
                    raise ValueError("Invalid STAP-A NAL length")
                emit(data[position:position + size])
                position += size
        elif kind == 28:  # FU-A: indicator + FU header + fragment bytes.
            if len(data) < 3:
                raise ValueError("Truncated FU-A")
            start, end = bool(data[1] & 0x80), bool(data[1] & 0x40)
            header = (data[0] & 0xE0) | (data[1] & 0x1F)
            if data[1] & 0x20 or (start and end):
                raise ValueError("Invalid FU-A flags")
            if start:
                if fragment is not None:
                    raise ValueError("Nested FU-A start")
                fragment = bytearray([header])
                fragment_header, fragment_timestamp = header, timestamp
            if fragment is None or header != fragment_header or timestamp != fragment_timestamp:
                raise ValueError("FU-A continuation without a matching start")
            fragment.extend(data[2:])
            if end:
                emit(fragment)
                fragment = None
        else:
            raise ValueError(f"Unsupported RTP H.264 packet type: {kind}")
    if fragment is not None or not sequences:
        raise ValueError("Incomplete or empty RTP stream")
    path = output / "01_stream.h264"
    path.write_bytes(video)
    src, sport, dst, dport, ssrc, pt = next(iter(flows))
    return {
        "source": str(capture.name), "source_sha256": sha256(capture.read_bytes()),
        "flow": f"{src}:{sport} -> {dst}:{dport}", "ssrc": ssrc,
        "payload_type": int(pt), "rtp_packets": len(sequences),
        "first_sequence": sequences[0], "last_sequence": sequences[-1],
        "sequence_continuous": True, "distinct_timestamps": len(timestamps),
        "marker_packets": markers, "rtp_packetization_types": dict(sorted(packet_types.items())),
        "reconstructed_nal_types": dict(sorted(nal_types.items())),
        "h264_bytes": len(video), "h264_sha256": sha256(video),
    }


def inspect_unknown(path):
    data = path.read_bytes()
    frequencies = Counter(data)
    entropy = -sum((count / len(data)) * math.log2(count / len(data))
                   for count in frequencies.values()) if data else 0.0
    blocks = [data[i:i + 16] for i in range(0, len(data) - 15, 16)]
    return {
        "source": path.name, "bytes": len(data), "sha256": sha256(data),
        "first_32_bytes_hex": data[:32].hex(), "entropy_bits_per_byte": entropy,
        "length_mod_16": len(data) % 16, "length_mod_32": len(data) % 32,
        "aligned_16_byte_blocks": len(blocks),
        "duplicate_aligned_16_byte_blocks": len(blocks) - len(set(blocks)),
        "note": "Statistical observations only; encryption algorithm is unconfirmed.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=BUNDLE / "attachments/streaming.pcapng")
    parser.add_argument("--unknown", type=Path, default=BUNDLE / "attachments/streaming_unknown.bin")
    parser.add_argument("--output", type=Path, default=BUNDLE / "results")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    video = extract(args.capture, args.output)
    unknown = inspect_unknown(args.unknown)
    summary = {"video": video, "unknown_attachment": unknown,
               "status": "Only stage 1 is reproducible; full Flag has not been recovered."}
    (args.output / "01_streaming_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Flow:", video["flow"])
    print(f"SSRC: {video['ssrc']}; Payload Type: {video['payload_type']}")
    print(f"RTP packets: {video['rtp_packets']}; sequence: {video['first_sequence']}..{video['last_sequence']} (continuous)")
    print("RTP packetization types:", video["rtp_packetization_types"])
    print("Reconstructed NAL types:", video["reconstructed_nal_types"])
    print(f"RTP marker packets: {video['marker_packets']}; distinct timestamps: {video['distinct_timestamps']}")
    print(f"H.264 bytes: {video['h264_bytes']}; SHA-256: {video['h264_sha256']}")
    print(f"Unknown attachment: {unknown['bytes']} bytes; entropy: {unknown['entropy_bits_per_byte']:.6f} bits/byte")
    print("Unknown SHA-256:", unknown["sha256"])
    print("Duplicate aligned 16-byte blocks:", unknown["duplicate_aligned_16_byte_blocks"])
    print("Status: full Flag has not been recovered; inspect the video manually for stage 1.")


if __name__ == "__main__":
    main()
