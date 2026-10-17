# How to Run CyberNinjas

### Quick Start
```bash
cd /home/ashish/Desktop/pro && ./start.sh
```
Or directly with Python:
```bash
cd /home/ashish/Desktop/pro && python3 main.py --port 8000
```

---

### Accessing the Dashboard
Open your web browser and navigate to:
**[http://localhost:8000](http://localhost:8000)**

---

### Command-Line Options
- Run on a different port:
  ```bash
  python3 main.py --port 8080
  ```
- Bind to specific network interface or IP:
  ```bash
  python3 main.py --host 0.0.0.0 --port 8000
  ```
- Run automated tests:
  ```bash
  python3 -m pytest tests/ -v
  ```

---

### Documentation Reference
For an architectural breakdown, API reference, and feature guides:
- [PROJECT_GUIDE.md](file:///home/ashish/Desktop/pro/PROJECT_GUIDE.md)
- [README.md](file:///home/ashish/Desktop/pro/README.md)
