import pytest
import os
import json
import pandas as pd
from pathlib import Path
from network_tools import NetworkDataProcessor, RegressionAnalyzer, NetworkVisualizer, HTMLReportGenerator  # Adjust import based on your module structure

# Fixture to create a temporary directory with sample JSON files
@pytest.fixture
def temp_results_dir(tmp_path):
    dir_path = tmp_path / "recon_results"
    dir_path.mkdir()
    targets = ["example.com"]
    scan_types = ["nmap", "ping", "traceroute", "sublist3r"]
    for target in targets:
        for scan_type in scan_types:
            file_name = f"{scan_type}_{target.replace('.', '_')}.json"
            file_path = dir_path / file_name
            if scan_type == "nmap":
                data = {
                    "scan_results": {
                        "nmap": {
                            "output": "Nmap scan report for example.com (93.184.216.34)\nHost is up (0.0012s latency).\nPORT   STATE SERVICE\n80/tcp open  http\n443/tcp open https\n"
                        }
                    }
                }
            elif scan_type == "ping":
                data = {
                    "scan_results": {
                        "ping": {
                            "output": "PING example.com (93.184.216.34): 56 data bytes\n64 bytes from 93.184.216.34: icmp_seq=0 ttl=56 time=11.632 ms\n--- example.com ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 11.632/11.632/11.632/0.000 ms"
                        }
                    }
                }
            elif scan_type == "traceroute":
                data = {
                    "scan_results": {
                        "traceroute": {
                            "output": "Hop #1\nHop #2\nHop #3"
                        }
                    }
                }
            elif scan_type == "sublist3r":
                data = {
                    "scan_results": {
                        "sublist3r": {
                            "output_file": str(dir_path / f"subdomains_{target}.txt")
                        }
                    }
                }
                # Create a sample subdomain file
                with open(dir_path / f"subdomains_{target}.txt", "w") as f:
                    f.write("sub1.example.com\nsub2.example.com")
            with open(file_path, 'w') as f:
                json.dump(data, f)
    return str(dir_path)

# Tests for NetworkDataProcessor
@pytest.mark.asyncio
async def test_load_scan_results(temp_results_dir):
    processor = NetworkDataProcessor(temp_results_dir)
    await processor.load_scan_results("example.com")
    assert "nmap" in processor.data
    assert "ping" in processor.data
    assert "traceroute" in processor.data
    assert "sublist3r" in processor.data
    assert "example.com" in processor.data["nmap"]
    assert processor.data["nmap"]["example.com"]["scan_results"]["nmap"]["output"]

@pytest.mark.asyncio
async def test_extract_metrics(temp_results_dir):
    processor = NetworkDataProcessor(temp_results_dir)
    await processor.load_scan_results("example.com")
    metrics = processor.extract_metrics()
    assert metrics["ports"]["example.com"] == [80, 443]
    assert len(metrics["services"]["example.com"]) == 2
    assert metrics["services"]["example.com"][0] == {"port": 80, "name": "http"}
    assert metrics["response_times"]["example.com"] == 11.632
    assert metrics["traceroute_hops"]["example.com"] == 3
    assert metrics["subdomains"]["example.com"] == ["sub1.example.com", "sub2.example.com"]
    assert "security_score" in metrics
    assert metrics["security_score"]["example.com"] == 90  # 100 - (2 ports * 5)

def test_calculate_security_scores(temp_results_dir):
    processor = NetworkDataProcessor(temp_results_dir)
    processor.metrics = {
        "ports": {"example.com": [22, 80, 443]},
        "vulnerabilities": {"example.com": ["VULNERABLE: CVE-123"]},
        "services": {"example.com": []},
        "response_times": {"example.com": None},
        "subdomains": {"example.com": []},
        "traceroute_hops": {"example.com": 0}
    }
    processor._calculate_security_scores()
    # Score: 100 - (3 ports * 5) - (1 vuln * 15) - (1 high-risk port 22 * 3) = 67
    assert processor.metrics["security_score"]["example.com"] == 67

# Tests for RegressionAnalyzer
def test_perform_regression():
    data = pd.DataFrame({
        "ports_open": [1, 2, 3],
        "vulns_found": [0, 1, 2],
        "response_time": [10, 20, 30],
        "traceroute_hops": [2, 3, 4],
        "subdomain_count": [0, 1, 2],
        "security_score": [90, 80, 70]
    })
    features = ["ports_open", "vulns_found", "response_time", "traceroute_hops", "subdomain_count"]
    analyzer = RegressionAnalyzer(data, features)
    results = analyzer.perform_regression()
    assert results is not None
    assert "coefficients" in results
    assert "mse" in results
    assert "r2" in results
    assert all(feature in results["coefficients"] for feature in features)
    assert isinstance(results["mse"], float)
    assert isinstance(results["r2"], float)

def test_perform_regression_insufficient_data():
    data = pd.DataFrame({
        "ports_open": [1],
        "vulns_found": [0],
        "response_time": [10],
        "security_score": [90]
    })
    features = ["ports_open", "vulns_found", "response_time"]
    analyzer = RegressionAnalyzer(data, features)
    results = analyzer.perform_regression()
    assert results is None  # Should return None for insufficient data

# Tests for NetworkVisualizer
def test_create_open_ports_chart(tmp_path):
    metrics = {"ports": {"example.com": [80, 443], "test.com": [22, 80]}}
    visualizer = NetworkVisualizer(metrics, str(tmp_path))
    result = visualizer.create_open_ports_chart()
    assert "html_file" in result
    assert "base64_image" in result
    assert os.path.exists(result["html_file"])
    assert result["title"] == "Open Ports by Target"

def test_create_security_score_chart(tmp_path):
    metrics = {"security_score": {"example.com": 90, "test.com": 50}}
    visualizer = NetworkVisualizer(metrics, str(tmp_path))
    result = visualizer.create_security_score_chart()
    assert "html_file" in result
    assert "base64_image" in result
    assert os.path.exists(result["html_file"])
    assert result["title"] == "Security Scores by Target"

# Tests for HTMLReportGenerator
def test_generate_html_report(tmp_path):
    metrics = {
        "ports": {"example.com": [80, 443]},
        "services": {"example.com": [{"port": 80, "name": "http"}, {"port": 443, "name": "https"}]},
        "vulnerabilities": {"example.com": []},
        "response_times": {"example.com": 11.632},
        "subdomains": {"example.com": ["sub1.example.com"]},
        "traceroute_hops": {"example.com": 3},
        "security_score": {"example.com": 90}
    }
    charts = {
        "open_ports_chart": {"base64_image": "dummy_base64_string"},
        "security_score_chart": {"base64_image": "dummy_base64_string"}
    }
    generator = HTMLReportGenerator(metrics, charts)
    output_file = str(tmp_path / "report.html")
    result = generator.generate_html_report(output_file)
    assert os.path.exists(result)
    with open(result, "r") as f:
        content = f.read()
        assert "Network Reconnaissance Report" in content
        assert "example.com" in content
        assert "dummy_base64_string" in content
