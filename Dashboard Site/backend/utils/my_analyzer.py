import pyshark
from collections import Counter
import asyncio
import pandas as pd
import os
import re

# مسار TShark على جهازك
TSHARK_PATH = r"E:\Mark\Wireshark\tshark.exe"

def analyze_file(filepath):
    filename = os.path.basename(filepath).lower()

    if filename.endswith('.pcap'):
        return analyze_pcap(filepath)

    elif filename.endswith('.csv'):
        return analyze_csv(filepath)

    else:
        return {'error': 'Unsupported file type'}

def analyze_pcap(filepath):
    try:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # فتح الملف باستخدام pyshark
        cap = pyshark.FileCapture(filepath, tshark_path=TSHARK_PATH)

        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        packets_preview = []
        count = 0

        for packet in cap:
            count += 1

            if len(packets_preview) < 10:
                try:
                    clean_str = re.sub(r'\x1b\[[0-9;]*m', '', str(packet))
                    packets_preview.append(clean_str)
                except Exception:
                    packets_preview.append(str(packet))

            if hasattr(packet, 'highest_layer'):
                protocols[packet.highest_layer] += 1

            if 'IP' in packet:
                try:
                    src_ips[packet.ip.src] += 1
                    dst_ips[packet.ip.dst] += 1
                except AttributeError:
                    pass

            if count >= 1000:
                break

        cap.close()

        # جمع كل الـ IPs الفريدة
        unique_ips = list(set(list(src_ips.keys()) + list(dst_ips.keys())))

        return {
            'type': 'pcap',
            'total_packets': count,
            'packets_preview': packets_preview,
            'protocols': dict(protocols.most_common(5)),
            'top_source_ips': dict(src_ips.most_common(5)),
            'top_destination_ips': dict(dst_ips.most_common(5)),
            'ips': unique_ips  # ✅ قائمة IPs
        }

    except Exception as e:
        return {'error': f"Error parsing pcap: {str(e)}"}

def analyze_csv(filepath):
    try:
        df = pd.read_csv(filepath)

        analysis = {
            'type': 'csv',
            'rows': len(df),
            'columns': list(df.columns),
            'preview': df.head(5).to_dict(orient='records')
        }

        # تحليل البروتوكولات
        if 'Protocol' in df.columns:
            analysis['top_protocols'] = df['Protocol'].value_counts().head(5).to_dict()

        if 'Source IP' in df.columns:
            analysis['top_source_ips'] = df['Source IP'].value_counts().head(5).to_dict()

        if 'Destination IP' in df.columns:
            analysis['top_destination_ips'] = df['Destination IP'].value_counts().head(5).to_dict()

        # استخراج IPs الفريدة
        source_ips = df['Source IP'].dropna().unique().tolist() if 'Source IP' in df.columns else []
        destination_ips = df['Destination IP'].dropna().unique().tolist() if 'Destination IP' in df.columns else []
        unique_ips = list(set(source_ips + destination_ips))

        analysis['ips'] = unique_ips  # ✅ قائمة IPs

        return analysis

    except Exception as e:
        return {'error': f"Error parsing CSV: {str(e)}"}
