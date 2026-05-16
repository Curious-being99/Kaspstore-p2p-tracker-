// scripts/radicle-helper.js
console.log("\n================================================================================");
console.log("🛠️  RADICLE P2P IDENTITY GENERATION TOOL (LOCAL MACHINE)");
console.log("================================================================================");
console.log("\nFollow these steps on your own computer to generate your secure Radicle secrets:");
console.log("\n1. Install Radicle CLI if you haven't (Linux/macOS):");
console.log("   curl -sSL https://radicle.xyz/install | sh");
console.log("\n2. Create your identity:");
console.log("   rad auth");
console.log("\n3. Get your RAD_PRIVATE_KEY (Base64 format):");
console.log("   cat ~/.radicle/keys/radicle.key | base64 | tr -d '\\\\n'");
console.log("\n4. Get your RAD_PASSPHRASE:");
console.log("   (This is the passphrase you entered during 'rad auth')");
console.log("\n5. Get your RAD_PROJECT_ID (once you publish your project):");
console.log("   rad init --name tracker-dashboard --description 'P2P Dash'");
console.log("\n================================================================================");
console.log("Once you have these, add them to Settings > Secrets in this project.");
console.log("================================================================================\n");
