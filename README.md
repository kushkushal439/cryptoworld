# POIS - Cryptographic Primitives Explorer

This project is a web-based educational tool for exploring the **Minicrypt Clique** of cryptographic primitives. It demonstrates the conceptual equivalence and standard reductions between fundamental cryptographic constructs, showing how you can build one primitive from another (for example, building a Pseudorandom Generator (PRG) from a One-Way Function (OWF), or a Pseudorandom Function (PRF) from a PRG).

## What it does

The core of the project models a "Clique" graph of cryptographic primitives:
- **One-Way Functions (OWF)**
- **One-Way Permutations (OWP)**
- **Pseudorandom Generators (PRG)**
- **Pseudorandom Functions (PRF)**
- **Pseudorandom Permutations (PRP)**
- **Message Authentication Codes (MAC)**

In theory (and in this app), these primitives can be reduced to one another. The backend (the "God" class) handles the reduction logic, knowing exactly how to construct the shortest path from a starting primitive to a target primitive using standard cryptographic constructions (like the GGM tree for PRG -> PRF, or Luby-Rackoff for PRF -> PRP). 

The web App allows you to visually explore these reductions, inspect the reduction chains, and see the interactive outputs of your cryptographic implementations in real time.

## Project Structure

- `backend/`: A Flask Python server that provides REST APIs and executes the "God" reduction logic and cryptographic primitive implementations.
- `frontend/`: A React + Vite web application where users can interactively visualize the clique and run reductions.
- `CryptoPrimitives/`: Base classes and structure for various cryptographic constructs.
- `Implementations/`: Concrete algorithms and code for the various primitives and transformations (e.g., GGM PRF, Merkle-Damgard, CBC, etc.).

## How to Run

### Backend (Flask Server)
1. Make sure you have Python installed.
2. Install the necessary Python backend dependencies (e.g., Flask, flask-cors). You might want to create a virtual environment first.
   ```bash
   pip install flask flask-cors pycryptodome
   ```
3. Run the backend server:
   ```bash
   cd backend
   python app.py
   ```
   *The server typically runs on port 5000.*

### Frontend (React App)
1. Make sure you have [Node.js](https://nodejs.org/) installed.
2. Navigate to the frontend directory and install dependencies:
   ```bash
   cd frontend
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
4. Open your browser to the local URL provided by Vite (usually `http://localhost:5173`) to explore the application!