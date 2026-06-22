# A-Analyzer: Developer Workflow & Update Guide

This guide provides a step-by-step developer workflow for making, testing, committing, and deploying updates to the A-Analyzer application.

---

## The Core Architecture (How it Works)
1. **Continuous Deployment**: Streamlit Community Cloud is connected directly to your GitHub repository. Every time you push a change to your tracked branch (usually `main`), Streamlit automatically detects it, builds the container, installs dependencies, and updates your live web app in real-time. **No manual clicks are needed.**
2. **Dynamic Database Routing**:
   * **In Cloud (Production)**: Connects to your **Supabase PostgreSQL** instance via the Connection Pooler URL in your Cloud secrets.
   * **Locally (Development/Offline)**: If no connection secrets are defined, the app automatically falls back to your local SQLite database (`data/campaign.db`). This allows you to test safely without altering production data.

---

## Step-by-Step Update Workflow

Follow these steps every time you want to make updates to the application:

### Step 1: Switch to a Local Feature Branch
It is best practice to keep `main` stable. Always make changes on a separate feature/update branch first:
```bash
# Switch to main and pull latest remote changes first
git checkout main
git pull origin main

# Create and switch to a new update/feature branch
git checkout -b my-new-feature
```

### Step 2: Develop and Test Locally
1. Start your local Streamlit development server:
   ```bash
   ./venv/bin/streamlit run dashboard.py
   ```
2. Open the local address in your browser (usually `http://localhost:8501`).
3. **Offline Testing (Default)**: Your local changes will read/write from your local SQLite database.
4. **Online Sandbox Testing (Optional)**: If you want your local app to connect to Supabase for testing, make sure your `.streamlit/secrets.toml` file contains the `SUPABASE_DB_URL` line.

### Step 3: Check and Commit Your Changes
Once you are happy with your changes locally, check and save them to Git:
```bash
# Check what files you have modified
git status

# Add files to the commit staging area
git add .

# Save the commit with a clear, descriptive message
git commit -m "feat: updated [feature/file name] to add [description]"
```

### Step 4: Merge Your Update into `main`
Now merge your feature branch back into your local stable `main` branch:
```bash
# 1. Switch back to your local main branch
git checkout main

# 2. Pull down any remote changes others might have pushed in the meantime
git pull origin main

# 3. Merge your new updates into main
git merge my-new-feature
```

### Step 5: Push to GitHub (Triggers Automatic Cloud Update)
Pushing to your GitHub repository is the magic step that launches your changes to the world:
```bash
# Push your merged main branch to GitHub
git push origin main
```

**Streamlit Community Cloud will immediately capture this push and begin deploying the updates.** You can check progress on your Streamlit Cloud dashboard.

### Step 6: Cleanup Your Local Branch (Optional)
Once your feature is merged and live, you can safely delete the local temporary branch:
```bash
git branch -d my-new-feature
```

---

## Special Scenarios

### 1. You updated Python Dependencies
If you installed a new Python library locally using pip:
1. Append the library name and version to **`requirements.txt`**.
2. Commit and push the `requirements.txt` file along with your code.
3. Streamlit Cloud will detect the updated requirements file, automatically restart the container, download the new packages, and compile them.

### 2. You updated Database Schema Tables
If you made changes to the database structure (such as adding a table or adding a new column to `apk_scans`):
1. Update the PostgreSQL/SQLite `CREATE TABLE` query inside the `init_db()` function in **`campaign/db.py`**.
2. Commit and push your code.
3. Because the app executes `init_db()` automatically on home page startup (`dashboard.py`), **your Supabase database tables will self-migrate and create any missing tables automatically on the next startup.**
4. *Note: If modifying or deleting existing columns, you may need to run direct `ALTER TABLE` SQL commands in your Supabase SQL Editor dashboard.*

### 3. Rotating API Keys or Database Passwords
If you rotate your VirusTotal API key, Gemini API key, or Supabase password:
1. Update your local **`.streamlit/secrets.toml`** file (never commit this file to Git!).
2. Go to your **Streamlit Community Cloud Dashboard** -> click **Settings** on your App -> select **Secrets**.
3. Update the values in the text block and click **Save**.
4. The cloud app will instantly reboot and load the updated keys.
