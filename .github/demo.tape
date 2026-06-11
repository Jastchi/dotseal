Output .github/demo.gif

Set FontSize 15
Set Width 1100
Set Height 500
Set Theme "tokyonight-storm"
Set Shell "bash"
Set Padding 20
Set Margin 30
Set MarginFill "#1a1b2e"
Set BorderRadius 10
Set WindowBar "Colorful"
Set WindowBarSize 28
Set TypingSpeed 50ms

# Set up env silently: correct PATH, clean prompt, clear screen so
# Show resumes on a blank terminal
Hide
Type "export PATH=$PATH:/Users/janfriedmann/Library/Python/3.9/bin && export PS1='$ ' && cd $(mktemp -d) && clear"
Enter
Sleep 400ms
Show

# Step 1 — generate master key
Type "dotseal init"
Enter
Sleep 1500ms

# Step 2 — write a sample .env
Type "cat > .env << 'EOF'"
Enter
Type "DATABASE_URL=postgres://user:pass@db.example.com/prod"
Enter
Type "API_KEY=sk-super-secret-key-1234"
Enter
Type "DEBUG=false"
Enter
Type "EOF"
Enter
Sleep 500ms

# Step 3 — encrypt
Type "dotseal encrypt"
Enter
Sleep 1500ms

# Step 4 — show .env.enc: keys plaintext, values sealed
Type "cat .env.enc"
Enter
Sleep 3000ms

# Step 5 — decrypt back to .env to prove the round-trip
Type "rm .env && dotseal decrypt && cat .env"
Enter
Sleep 6000ms
