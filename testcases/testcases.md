# 🧪 Test Cases – Command Injection Detection System

This file contains sample test cases used to validate the functionality of the Command Injection Detection tool.

---

## 🔴 TC1: Direct Command Injection

### Input

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char cmd[100];
    scanf("%s", cmd);
    system(cmd);
}
```

### Expected Output

* Vulnerability detected
* Severity: HIGH

---

## 🟢 TC2: Safe Constant Command

### Input

```c
#include <stdlib.h>

int main() {
    system("ls -l");
}
```

### Expected Output

* No vulnerability detected

---

## 🟡 TC3: Indirect Injection (Propagation)

### Input

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char input[100];
    char cmd[200] = "ls ";

    scanf("%s", input);
    strcat(cmd, input);
    system(cmd);
}
```

### Expected Output

* Vulnerability detected
* Severity: HIGH

---

## 🔵 TC4: snprintf Injection

### Input

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char input[100];
    char cmd[200];

    scanf("%s", input);
    snprintf(cmd, sizeof(cmd), "ls %s", input);
    system(cmd);
}
```

### Expected Output

* Vulnerability detected
* Severity: HIGH

---

## 🟣 TC5: C++ Input Injection

### Input

```cpp
#include <iostream>
#include <cstdlib>
using namespace std;

int main() {
    string cmd;
    cin >> cmd;
    system(cmd.c_str());
}
```

### Expected Output

* Vulnerability detected
* Severity: HIGH

---

## ⚪ TC6: Sanitized Input

### Input

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int isSafe(char *input) {
    return strchr(input, ';') == NULL;
}

int main() {
    char cmd[100];
    scanf("%s", cmd);

    if (isSafe(cmd)) {
        system(cmd);
    }
}
```

### Expected Output

* No vulnerability OR reduced severity

---

## 🧾 Summary

| Test Case | Type               | Expected Result |
| --------- | ------------------ | --------------- |
| TC1       | Direct Injection   | HIGH            |
| TC2       | Safe Code          | SAFE            |
| TC3       | Indirect Injection | HIGH            |
| TC4       | snprintf Injection | HIGH            |
| TC5       | C++ Case           | HIGH            |
| TC6       | Sanitized Input    | SAFE            |

---

## ✅ Notes

* All test cases are designed to validate taint analysis.
* Covers source → propagation → sink model.
* Includes both vulnerable and safe scenarios.

---
