
# 🛡️ Command Injection Detection using Compiler-Based Static Analysis

> 🚀 A compiler-integrated security analysis tool that detects command injection vulnerabilities at **compile time** using **AST traversal and taint analysis**.

---

## 📌 Problem Statement

Command Injection is a critical vulnerability where untrusted user input is executed as a system command, leading to:

* Unauthorized system access
* Data leakage
* Full system compromise

Most existing tools detect such vulnerabilities **only at runtime** or are too complex to integrate into development workflows.

---

## 💡 Proposed Solution

This project introduces a **lightweight, compiler-based static analysis system** that detects command injection vulnerabilities **before execution**, directly during compilation.

It leverages:

* **Clang/LLVM AST**
* **Taint Analysis (Source → Propagation → Sink)**
* **Rule-based detection engine**

---

## ✨ Key Features

* ⚡ **Compile-time vulnerability detection**
* 🔍 Accurate **taint tracking across variables**
* 🧠 AST-based program analysis
* 📊 Severity classification (HIGH / MEDIUM / LOW)
* 🌐 Interactive web interface (terminal-style)
* 🔒 No runtime overhead

---

## 🧱 System Architecture

```text
User
  │
  ▼
Frontend (HTML/CSS/JS)
  │
  ▼
Flask Backend (API)
  │
  ▼
Clang Parser → AST
  │
  ▼
Taint Analysis Engine
  │
  ▼
Sink Detection (system, exec)
  │
  ▼
Structured Vulnerability Report
```

---

## ⚙️ Tech Stack

| Component       | Technology              |
| --------------- | ----------------------- |
| Language        | C, C++                  |
| Compiler        | LLVM / Clang            |
| Backend         | Python (Flask)          |
| Frontend        | HTML, CSS, JavaScript   |
| Analysis Method | Static + Taint Analysis |

---

## 📂 Project Structure

```text
Command-Injection-Detector/
│
├── taint_analysis.cpp     # Core LLVM analysis engine
├── backend.py             # Flask server
├── templates/
│   └── index.html         # Frontend interface
├── test_cases/            # Sample programs
└── README.md
```

---

## 🔬 How It Works

### 1. Source Detection

Identifies untrusted input:

```c
scanf("%s", cmd);
cin >> cmd;
```

### 2. Taint Propagation

Tracks data flow:

```c
strcpy(buffer, cmd);
```

### 3. Sink Detection

Detects dangerous usage:

```c
system(buffer);
```

### ⚠️ Detection Rule

```text
If (Tainted Variable → Dangerous Function) → Vulnerability
```

---

## ▶️ Setup & Installation

### 🔧 Prerequisites

* LLVM / Clang installed
* Python 3.x
* Flask

### 📥 Steps

```bash
git clone <your-repo-link>
cd Command-Injection-Detector

# Compile analyzer
g++ taint_analysis.cpp -o taint_analysis `llvm-config --cxxflags --ldflags --libs`

# Install backend dependencies
pip install flask

# Run server
python backend.py
```

### 🌐 Open in Browser

```text
http://127.0.0.1:5000
```

---

## 🧪 Sample Cases

### 🔴 Vulnerable Code

```c
scanf("%s", cmd);
system(cmd);
```

**Output:**

```text
[VULNERABILITY] Command Injection
[SEVERITY] HIGH
```

---

### 🟢 Safe Code

```c
system("ls -l");
```

**Output:**

```text
[OK] No vulnerabilities detected
```

---

### 🟡 Indirect Injection

```c
scanf("%s", input);
strcat(cmd, input);
system(cmd);
```

---

## 📊 Detection Rules

| Category | Functions                         |
| -------- | --------------------------------- |
| Sources  | scanf, gets, fgets, cin, getenv   |
| Sinks    | system, execvp, popen             |
| Medium   | strcpy, strcat, sprintf, snprintf |

---

## 📈 Performance Summary

| Metric             | Result |
| ------------------ | ------ |
| Detection Accuracy | High   |
| False Positives    | Medium |
| Execution Time     | Fast   |

---

## 🏆 Advantages

* ✅ Early detection (before execution)
* ✅ No runtime overhead
* ✅ Lightweight and fast
* ✅ Easy integration into build pipelines
* ✅ Clear and explainable output

---

## ⚠️ Limitations

* Static analysis only
* Limited sanitization recognition
* Cannot detect runtime-generated commands

---

## 🔮 Future Enhancements

* SQL Injection detection
* Hybrid (static + dynamic) analysis
* Machine learning-based detection
* IDE plugin (VS Code extension)

---

## 🧠 Research Contribution

This project addresses a key gap:

> ❗ Lack of simple, compiler-integrated solutions for command injection detection

By embedding security checks into the compiler phase, it enables:

* Early vulnerability detection
* Improved secure coding practices
* Reduced dependency on external tools

---

## 📚 References

* OWASP Command Injection Guide
* MITRE CWE-77
* LLVM/Clang Documentation
* PortSwigger Web Security Academy

---

## 👨‍💻 Author

**B. Vikranth**
Roll No: 24CSB0B12

---

## ⭐ Final Note

This project demonstrates how **compiler design principles can be extended to real-world security problems**, bridging the gap between academic concepts and practical applications.

---
