#!/bin/bash
# Quick setup script for DevOpsConf demo

set -e

echo "🚀 Setting up Drift Remediation System..."
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.10+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "✅ Found Python $PYTHON_VERSION"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo "✅ Setup complete!"
echo ""
echo "📝 Next steps:"
echo "   1. Copy .env.example to .env:"
echo "      cp .env.example .env"
echo ""
echo "   2. Add your OpenAI API key to .env:"
echo "      OPENAI_API_KEY=sk-..."
echo ""
echo "   3. Run the demo:"
echo "      source venv/bin/activate"
echo "      cd demo/"
echo "      python run_demo.py"
echo ""
echo "🎯 Ready for DevOpsConf! Good luck with your presentation!"
