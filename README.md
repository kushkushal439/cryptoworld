# POIS: The Epic Cryptoworld 🌐🔐

Welcome to the implementation of the Minicrypt Clique for our Principles of Information Security (POIS) project. 

Our architecture is designed to be highly modular, functional, and strictly compliant with the "No-Library Rule". We use a graph-routing approach to automatically chain cryptographic reductions.

## 🏗️ Architecture Overview

The codebase is split into three main parts:

1. **`Primitive_enums.py`**: Contains the `Primitive` enum (OWF, PRG, PRF, etc.). This ensures type safety across the graph.
2. **`CryptoPrimitives/` (The Wrappers)**: Contains base container classes (e.g., `OWF`, `PRG`). We use **Composition over Inheritance**. Instead of writing a new class for every math equation, we pass a pure `logic_func` into these containers.
3. **`God.py` (The Router)**: The omniscient orchestrator. It holds the adjacency list of the Minicrypt graph and uses BFS to find the shortest reduction path from Primitive A to Primitive B, chaining conversions along the way.

## 🚀 How to Work on Your Assignment (PA_i)

**Rule of Thumb:** Keep all your math, logic, tests, and conversions inside your specific assignment file. Do NOT bloat `God.py` or the `CryptoPrimitives` folder with assignment-specific math.

Example: If you are working on PA #1 (OWF to PRG), follow these exact steps:

### Step 1: Create your implementation file
Create a file for your assignment (e.g., `implementations/PA1.py`).

### Step 2: Write your pure logic function
Write the core math without worrying about classes.

```python
# implementations/PA1.py

def hill_prg_logic(seed, length, owf_instance):
    # 1. Use owf_instance.evaluate()
    # 2. Extract hard-core bits
    # 3. Return the pseudorandom stream
    pass