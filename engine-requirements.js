const major = parseInt(process.versions.node.split(".")[0], 10);

if (major < 20) {
    console.error(
        "\n========================================\n" +
        " Baileys requires Node.js 20+ to run  \n" +
        "----------------------------------------\n" +
        `   You are using Node.js ${process.versions.node}\n` +
        "   Please upgrade to Node.js 20+ to proceed.\n" +
        "========================================\n"
    );
    process.exit(1);
}