#!/bin/bash
# ============================================================
# MalGuise Framework - Automated Setup Script
# ============================================================
# This script sets up the MalGuise framework on a new machine.
# Run this script from inside the MalGuise/ directory.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
# ============================================================

set -e

echo "============================================================"
echo "MalGuise Framework Setup"
echo "============================================================"

# Step 1: Install system-level Python dependencies
echo ""
echo "[1/3] Installing system Python dependencies..."
pip install -r requirements.txt

# Step 2: Create detector virtual environment (det_venv)
echo ""
echo "[2/3] Setting up detector virtual environment (det_venv)..."
DET_VENV_DIR="detector/det_venv"

if [ -d "$DET_VENV_DIR" ]; then
    echo "  det_venv already exists. Skipping creation."
else
    python3 -m venv "$DET_VENV_DIR"
    echo "  Created virtual environment at $DET_VENV_DIR"
fi

# Install detector dependencies into det_venv
"$DET_VENV_DIR/bin/pip" install --upgrade pip
"$DET_VENV_DIR/bin/pip" install -r requirements_det.txt

echo ""
echo "[3/3] Verifying setup..."

# Quick sanity check
python3 -c "import angr; import lief; print('  System Python: angr + lief OK')"
"$DET_VENV_DIR/bin/python3" -c "import angr; import lief; import glog; import torch; print('  det_venv: angr + lief + glog + torch OK')"

echo ""
echo "============================================================"
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Place your test malware .exe files in data/Test/<FamilyName>/"
echo "  2. Run the batch evaluation:"
echo "     MPLCONFIGDIR=/tmp/matplotlib python3 scripts/batch_evaluate.py --c-budget 40 --max-length 6 --workers 24 --timeout 1800 --resume"
echo ""
echo "  If the machine is low on disk space in /tmp, use --workers 16."
echo "============================================================"
