Output .github/demo.gif

Set FontSize 13
Set Width 800
Set Height 420
Set Theme "Catppuccin Mocha"
Set Shell "bash"
Set Padding 24
Set TypingSpeed 40ms

# Silence the shell prompt noise and set up a clean PATH
Hide
Type "export PS1='$ ' && export PATH=$PATH:/Users/janfriedmann/Library/Python/3.9/bin && cd $(mktemp -d) && clear"
Enter
Sleep 300ms
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
Sleep 9000ms
