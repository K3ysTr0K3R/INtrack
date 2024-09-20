#!/bin/bash

# Function to safely display file contents with clear output and error handling
enumerate_system(){
    echo ""
    echo "[+] Directory listing of /etc:"
    echo ""
    ls -al /etc || echo "[-] Error: Unable to list /etc directory"

    echo ""
    echo "[+] Recursive listing of /etc:"
    echo ""
    ls -R /etc || echo "[-] Error: Unable to recursively list /etc"

    echo ""
    echo "[+] List of running processes:"
    echo ""
    ps -ef || echo "[-] Error: Unable to list processes"

    echo ""
    echo "[+] List of active network connections:"
    echo ""
    netstat -tunap || echo "[-] Error: Unable to list network connections"

    # Check for /etc/config/ directory and list its contents
    if [ -d "/etc/config/" ]; then
        echo "[+] Directory listing of /etc/config:"
        echo ""
        ls -al /etc/config || echo "[-] Error: Unable to list /etc/config directory"

        echo ""
        for file in /etc/config/*; do
            echo "[+] Contents of $file:"
            cat "$file" || echo "[-] Error: Unable to read $file"
            echo ""
        done
    else
        echo ""
        echo "[+] /etc/config directory not found"
        echo ""
    fi

    # Securely check and read /etc/passwd and /etc/shadow
    echo "[+] Checking /etc/passwd and /etc/shadow files"

    if [ -f "/etc/passwd" ]; then
        echo "[+] Contents of /etc/passwd:"
        cat /etc/passwd || echo "[-] Error: Unable to read /etc/passwd"
    else
        echo "[-] /etc/passwd file not found"
    fi

    if [ -f "/etc/shadow" ]; then
        echo "[+] Contents of /etc/shadow (requires root):"
        sudo cat /etc/shadow || echo "[-] Error: Unable to read /etc/shadow"
    else
        echo "[-] /etc/shadow file not found"
    fi
}

enumerate_system
