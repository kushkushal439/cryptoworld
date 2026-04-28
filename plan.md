## Plan: Minicrypt Web Explorer Application

The web app requires a React frontend connected to the existing Python codebase. We will build a FastAPI backend to expose `God.py` logic and a Vite+React+TypeScript frontend styled with TailwindCSS matching the three-tier specification.

**Steps**
1. **API Backend Setup (FastAPI)**
   - Create a `backend/main.py` utilizing `FastAPI` to expose the Minicrypt Graph logic and handle conversions.
   - Implement an endpoint (e.g., `/api/reduce`) that accepts foundation, source primitive, target primitive, and input data.
   - Handle "stub" responses for unimplemented conversions properly to return "Not implemented yet (due: PA#N)" based on the specification.
2. **Frontend Scaffolding** (*parallel with step 1*)
   - Initialize the app using `npm create vite@latest frontend -- --template react-ts`.
   - Install and configure Tailwind CSS.
3. **Frontend Components Implementation**
   - **`App.tsx`**: Main container managing global state (selected Foundation, Source, Target, bidirectional state).
   - **`TopBar.tsx`**: The top-level foundation toggle (AES-128 / DLP).
   - **`BuildPanel.tsx` (Column 1)**: Component defining the Source primitive, taking hex input, and rendering the trace steps (sub-reductions from foundation to source).
   - **`ReducePanel.tsx` (Column 2)**: Component defining the Target primitive, taking query input, and rendering the reduction from Source to Target.
   - **`ProofSummary.tsx`**: Bottom collapsible box mapping the (Foundation → A → B) chain, displaying theorems (HILL, GGM, etc.) and security claims.
4. **State Management & Integration**
   - Implement data fetching (e.g., using `fetch` or `axios` in a custom hook) from the React application to the FastAPI endpoints.
   - Ensure real-time UI updates (no page reload) whenever drop-downs or text keys change (using debounced inputs or direct on-change triggers).

**Relevant files**
- `backend/main.py` — (To be created) The FastAPI wrapper interfacing with `God.py`.
- `God.py` — May need minor modifications to accurately trace intermediate steps and map them to PA numbers for the API response.
- `frontend/src/App.tsx` — Main application orchestrator for the UI.
- `frontend/src/components/*` — (To be created) Reusable React/Tailwind components.

**Verification**
1. Run `uvicorn dev backend/main.py --host 0.0.0.0 --reload` to start the backend and verify endpoints using the interactive `/docs`.
2. Run `npm run dev` in the frontend directory.
3. Test layout conformity: verify the TopBar, Column1 (Build Panel), Column2 (Reduce Panel), and Bottom box (Proof Summary) are precisely arranged.
4. Test the stubs: select a supported but unimplemented pair and verify the "Not implemented yet (due: PA#N)" placeholder shows up correctly in the trace.
5. Test the routing table UI: verify backward toggle exists and handles unsupported path errors smoothly.

**Decisions**
- **Separation of concerns:** Python handles the core cryptographic logic and tracing; React focuses strictly on the visual presentation and intermediate step breakdown.
- **Architectural Rule Enforcement:** The backend API must explicitly split the `Foundation → Source` trace (Run 1) and the `Source → Target` trace (Run 2). This ensures Column 2 never directly uses the Foundation, enforcing the black-box abstraction required.
- **Incremental completeness:** For PA#0, missing algorithms return stubbed hex traces and flag incomplete UI steps, keeping you compliant with the specs without preventing you from building the UI iteratively.