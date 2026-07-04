#!/bin/bash

echo "=========================================="
echo "Sandlock Benchmark - $(date)"
echo "=========================================="

# 测试函数
benchmark() {
    local name="$1"
    local cmd="$2"
    local runs=10
    
    # 预热
    eval "$cmd" >/dev/null 2>&1 || true
    
    # 计时
    local total=0
    for i in $(seq 1 $runs); do
        start=$(date +%s%N)
        eval "$cmd" >/dev/null 2>&1
        end=$(date +%s%N)
        elapsed=$(( (end - start) / 1000000 ))
        total=$((total + elapsed))
    done
    
    avg=$((total / runs))
    echo "$name: ${avg}ms"
}

echo ""
echo "=== 基准测试 (无沙箱) ==="
benchmark "echo baseline" "echo hello"
benchmark "python3 baseline" "python3 -c 'print(1)'"
benchmark "sh baseline" "sh -c 'echo hello'"

echo ""
echo "=== Sandlock 普通模式 ==="
benchmark "echo + sandlock" "./sandlock -- echo hello"
benchmark "python3 + sandlock" "./sandlock -- python3 -c 'print(1)'"
benchmark "sh + sandlock" "./sandlock -- sh -c 'echo hello'"

echo ""
echo "=== Sandlock 全开 ==="
benchmark "echo full" "./sandlock --no-network --no-fork --clean-env --cpu 5 --mem 256 -- echo hello"
benchmark "python3 full" "./sandlock --no-network --no-fork --clean-env --cpu 5 --mem 256 -- python3 -c 'print(1)'"

echo ""
echo "=== Sandlock strict模式 ==="
benchmark "echo strict" "./sandlock --strict --allow /tmp --allow /usr -- echo hello"
benchmark "python3 strict" "./sandlock --strict --allow /tmp --allow /usr -- python3 -c 'print(1)'"

echo ""
echo "=== Python sandbox (lang/python) ==="
echo 'print(1)' > /tmp/bench_code.py
benchmark "python sandbox" "python3 lang/python/sandbox.py /tmp/bench_code.py --timeout 5"

echo ""
echo "=== 组合测试 ==="
benchmark "sandlock + py sandbox" "./sandlock --cpu 5 --mem 256 -- python3 lang/python/sandbox.py /tmp/bench_code.py --timeout 5"

