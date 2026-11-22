
import argparse
import json
from pathlib import Path

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def main():
    parser = argparse.ArgumentParser(description="Analyseur IDS/IPS TP1")
    parser.add_argument("--pcap", required=True, help="Chemin du fichier PCAP")
    parser.add_argument("--out", required=True, help="Chemin du rapport JSON")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.is_file():
        parser.error(f"Fichier PCAP introuvable : {pcap_path}")

    logger.info("Démarrage de l'analyse TP1")

    capture = Capture(pcap_file=str(pcap_path))
    capture.capture_traffic()
    capture.analyse()

    report_data = {
        "protocols": capture.get_protocol_counts(),
        "attacks": capture.attacks,
        "flag": capture.flag,
    }

    json_path = Path(args.out)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=2, ensure_ascii=False)

    pdf_path = json_path.with_suffix(".pdf")
    report = Report(capture, str(pdf_path), capture.get_summary())
    report.generate("graph")
    report.generate("array")
    report.save()

    print(f"Rapport JSON : {json_path}")
    print(f"Rapport PDF  : {pdf_path}")


if __name__ == "__main__":
    main()

