export const en = {
  // Header
  offlineMode: "OFFLINE MODE",
  offlineDisclaimer: "Browser online/offline status is NOT a cryptographic guarantee. Ensure air-gapped usage manually.",
  noNetworkNote: "No network calls — static build",

  // Footer
  tailsTitle: "How to use on Tails OS",
  tailsLine1: "Copy the dist/ folder to a USB stick.",
  tailsLine2: "Open index.html in the Tor Browser (file://) with network disabled.",
  tailsLine3: "Never photograph or screenshot your seed phrase.",
  tailsLine4: "Verify addresses and amounts carefully before signing.",
  tailsLine5: "Prefer trusted unsigned transaction files.",

  // Navigation
  home: "Home",
  createWallet: "Create Wallet",
  signTransaction: "Sign Transaction",

  // Hub
  hubTitle: "TRON Cold Wallet",
  hubSubtitle: "Air-gapped wallet generation and transaction signing",
  hubCreateDesc: "Generate a new TRON wallet with a BIP39 mnemonic seed phrase. Offline and secure.",
  hubSignDesc: "Sign an unsigned transaction file with your mnemonic. No network required.",

  // Step indicator
  stepOf: "Step {current} of {total}",

  // Create wallet — PreScreen
  preScreenTitle: "Before You Begin",
  preScreenWarning: "Your seed phrase will be shown once. If you lose it, you lose access to your funds permanently. There is no recovery option.",
  preScreenNoPhotos: "Do not photograph or screenshot the seed phrase.",
  preScreenNoCloud: "Do not save the seed phrase in cloud storage or any connected device.",
  preScreenCheck1: "I understand my seed phrase is shown once and I must write it down on paper",
  preScreenCheck2: "I will not photograph, screenshot, or digitally copy the seed phrase",
  preScreenCheck3: "I understand that losing the seed phrase means permanent loss of funds",
  continue: "Continue",
  back: "Back",

  // Create wallet — GenerationSettings
  genTitle: "Generation Settings",
  wordCount: "Seed phrase length",
  words12: "12 words",
  words24: "24 words",
  passphrase: "BIP39 Passphrase (optional)",
  passphraseHint: "Advanced. Leave empty if unsure.",
  passphraseConfirm: "Confirm passphrase",
  passphraseMismatch: "Passphrases do not match",
  generateWallet: "Generate Wallet",
  generating: "Generating…",

  // Create wallet — SeedDisplay
  seedTitle: "Your Seed Phrase",
  seedWarning: "Write these words down on paper. Do NOT copy digitally.",
  seedHidden: "Seed phrase hidden",
  showSeed: "Show seed phrase",
  hideSeed: "Hide seed phrase",
  seedAutoHide: "Auto-hides in {seconds}s",
  seedTimerExpired: "Seed hidden for safety. Click Show to reveal again.",

  // Create wallet — SeedConfirm
  confirmTitle: "Confirm Your Seed",
  confirmInstruction: "Enter the requested words from your seed phrase to confirm you wrote them down.",
  wordNumber: "Word #{n}",
  wordIncorrect: "Incorrect word",
  allCorrect: "All words confirmed correctly",

  // Create wallet — AddressDisplay
  addressTitle: "Your TRON Address",
  addressBase58: "Address (Base58)",
  addressHex: "Address (Hex)",
  showFullAddress: "Show full address",
  hideFullAddress: "Hide full address",
  qrPlaceholder: "QR code placeholder",
  copyAddress: "Copy Address",

  // Create wallet — FinalConfirm
  finalTitle: "Final Confirmation",
  finalCheck1: "I have written down the seed phrase on paper",
  finalCheck2: "I have verified the public address is correct",
  finalCheck3: "I understand that only the seed phrase can recover this wallet",
  finish: "Finish",
  walletCreated: "Wallet Created Successfully",
  returnHome: "Return to Home",

  // Sign — ImportTx
  importTitle: "Import Unsigned Transaction",
  importInstruction: "Select or drag and drop an unsigned transaction JSON file.",
  dragDrop: "Drag & drop file here",
  orClickBrowse: "or click to browse",
  fileName: "File",
  fileSize: "Size",
  fileSha256: "SHA-256",
  computing: "Computing…",
  next: "Next",

  // Sign — TxReview
  reviewTitle: "Review Transaction",
  txType: "Type",
  txFrom: "From",
  txTo: "To",
  txToken: "Token / Contract",
  txAmount: "Amount",
  txFeeLimit: "Fee Limit",
  antiSubstitutionTitle: "Anti-substitution verification",
  antiSubstitutionWarning: "The signature binds to raw_data_hex / txID below, NOT the human-readable summary above. If the file was tampered with, the summary may not match the actual transaction data. Treat the hex and ID as authoritative.",
  txId: "Transaction ID",
  rawDataHex: "raw_data_hex",
  showRawHex: "Show raw_data_hex",
  hideRawHex: "Hide raw_data_hex",
  reviewCheck1: "I have verified the recipient address and amount",
  reviewCheck2: "I understand the signature binds to raw_data_hex, not the summary",
  reviewCheck3: "I have verified this transaction on a trusted source",
  last4Challenge: "Enter the last 4 characters of the recipient address",
  last4Incorrect: "Characters do not match",
  continueToSigning: "Continue to Signing",
  warnings: "Warnings",

  // Sign — SigningStep
  signingTitle: "Sign Transaction",
  mnemonicLabel: "Mnemonic seed phrase",
  mnemonicPlaceholder: "Enter your seed phrase words separated by spaces",
  passphraseLabel: "BIP39 Passphrase (if used during creation)",
  addressIndex: "Address index",
  addressIndexHint: "Usually 0. Integer from 0 to 99.",
  derivationPath: "Derivation path",
  signButton: "Sign Transaction",
  signing: "Signing…",
  mnemonicRequired: "Mnemonic is required",
  invalidIndex: "Enter a valid integer from 0 to 99",

  // Sign — SignResult
  resultTitle: "Transaction Signed",
  signedSize: "Signed file size",
  signedSha256: "Signed SHA-256",
  downloadSigned: "Download Signed JSON",
  copySigned: "Copy Signed JSON",
  bytes: "bytes",

  // Modals
  confirmCopyTitle: "Confirm Copy",
  confirmCopyMessage: "You are about to copy sensitive data to the clipboard. Clipboard contents may be accessible to other applications. Continue?",
  confirmCopyCancel: "Cancel",
  confirmCopyProceed: "Copy to Clipboard",
  copied: "Copied!",

  // Status chips
  statusOffline: "Offline",
  statusAirGapped: "Air-Gapped",
  statusStaticBuild: "Static Build",
} as const;

export type TranslationKey = keyof typeof en;
