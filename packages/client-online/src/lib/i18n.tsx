import React, { createContext, useContext, useState, useCallback } from "react";

const en = {
  appTitle: "TRON Offline Signer",
  langToggle: "RU",
  trustBannerTitle: "Security Notice",
  trustBannerBody: "This online device is NOT trusted for handling private keys or secrets. Always verify transaction details on your offline (air-gapped) signing device before approving.",
  footerNote: "UI Prototype — No real transactions are performed.",
  homeTitle: "TRON Offline Transaction Tool",
  homeSubtitle: "Create unsigned transactions or broadcast signed ones.",
  createCardTitle: "Create Unsigned Transaction",
  createCardDesc: "Build an unsigned TRX or TRC20 transfer to sign offline.",
  broadcastCardTitle: "Broadcast Signed Transaction",
  broadcastCardDesc: "Upload a signed transaction JSON and broadcast it to the network.",
  goToCreate: "Create Transaction",
  goToBroadcast: "Broadcast Transaction",
  stepOf: "Step {current} of {total}",
  networkLabel: "Network",
  mainnet: "Mainnet",
  shasta: "Shasta",
  fullHostOverride: "Full Node URL (optional)",
  fullHostPlaceholder: "Leave empty to use default",
  fromAddress: "From Address",
  toAddress: "To Address",
  assetType: "Asset Type",
  assetTrx: "TRX (native)",
  assetUsdt: "USDT TRC20",
  assetCustom: "Custom TRC20",
  amountTrx: "Amount (TRX)",
  amountToken: "Amount (Token)",
  contractAddress: "Contract Address",
  decimals: "Decimals",
  decimalsLocked: "Decimals (locked)",
  nextReview: "Next: Review",
  invalidAddress: "Invalid TRON address",
  addressesMustDiffer: "From and To addresses must be different",
  amountMustBePositive: "Amount must be greater than 0",
  amountTooLarge: "Amount is too large for safe conversion",
  invalidDecimals: "Decimals must be 0–18",
  suspiciousAddress: "Warning: the recipient address looks suspicious. Please double-check.",
  invalidUrl: "Invalid URL format",
  reviewTitle: "Review Transaction",
  reviewNetwork: "Network",
  reviewFullHost: "Full Node URL",
  reviewAsset: "Asset",
  reviewFrom: "From",
  reviewTo: "To",
  reviewAmountTrx: "Amount (TRX)",
  reviewAmountSun: "Amount (SUN)",
  reviewAmountToken: "Amount (Token)",
  reviewSmallestUnit: "Smallest Unit",
  reviewContract: "Token Contract",
  reviewDecimals: "Decimals",
  checkVerifyAddresses: "I have carefully verified the recipient and sender addresses.",
  checkUnderstandFunds: "I understand that this file, once signed and broadcast, can move real funds.",
  checkCompareOffline: "I will compare these details again on my offline signing device.",
  exportButton: "Build & Export Unsigned TX",
  building: "Building…",
  protoDisclaimer: "UI prototype uses mocked build; not real unsigned tx building.",
  doneTitle: "File Ready",
  doneTxId: "Transaction ID",
  doneNetwork: "Network Host",
  backToForm: "Back to Form",
  goHome: "Home",
  pickFileTitle: "Select Signed Transaction",
  pickFileButton: "Choose Signed JSON File",
  pickFileDesc: "Select a .json file containing a signed transaction.",
  fileInvalidJson: "File does not contain valid JSON.",
  fileMissingTxId: "Missing or empty txID field.",
  fileMissingRawData: "Missing raw_data object.",
  fileMissingRawHex: "Missing or empty raw_data_hex field.",
  fileMissingSignature: "Missing or empty signature array.",
  fileInvalidSignatureItem: "Signature array contains empty entries.",
  previewTitle: "Transaction Preview",
  previewTxId: "Transaction ID",
  previewType: "Type",
  previewFrom: "From",
  previewTo: "To",
  previewAmount: "Amount",
  previewFeeLimit: "Fee Limit",
  previewContract: "Token Contract",
  previewToken: "Token",
  previewWarnings: "Warnings",
  previewDecodeFailed: "Could not decode transaction data for preview.",
  verifyCheckbox: "I have verified this transaction on my offline device.",
  irreversibleWarning: "Broadcasting a transaction is irreversible. Once submitted, funds cannot be recovered.",
  sendButton: "Send Transaction",
  sending: "Sending…",
  resultSuccessTitle: "Transaction Submitted",
  resultSuccessTxId: "Transaction ID",
  resultFailTitle: "Could Not Broadcast",
  technicalDetails: "Technical Details",
  notFoundTitle: "Page Not Found",
  notFoundDesc: "The page you're looking for doesn't exist.",
  unknown: "Unknown",
  trxTransfer: "TRX Transfer",
  trc20Transfer: "TRC20 Transfer",
  sun: "SUN",
} as const;

const ru: Record<keyof typeof en, string> = {
  appTitle: "TRON Офлайн Подпись",
  langToggle: "EN",
  trustBannerTitle: "Уведомление о безопасности",
  trustBannerBody: "Это онлайн-устройство НЕ является доверенным для работы с приватными ключами. Всегда проверяйте данные транзакции на офлайн (изолированном) устройстве перед подтверждением.",
  footerNote: "UI прототип — реальные транзакции не выполняются.",
  homeTitle: "TRON Офлайн Инструмент",
  homeSubtitle: "Создавайте неподписанные транзакции или транслируйте подписанные.",
  createCardTitle: "Создать неподписанную транзакцию",
  createCardDesc: "Сформировать неподписанный перевод TRX или TRC20 для офлайн подписи.",
  broadcastCardTitle: "Транслировать подписанную транзакцию",
  broadcastCardDesc: "Загрузите подписанную транзакцию в формате JSON и отправьте в сеть.",
  goToCreate: "Создать транзакцию",
  goToBroadcast: "Транслировать транзакцию",
  stepOf: "Шаг {current} из {total}",
  networkLabel: "Сеть",
  mainnet: "Mainnet",
  shasta: "Shasta",
  fullHostOverride: "URL ноды (необязательно)",
  fullHostPlaceholder: "Оставьте пустым для значения по умолчанию",
  fromAddress: "Адрес отправителя",
  toAddress: "Адрес получателя",
  assetType: "Тип актива",
  assetTrx: "TRX (нативный)",
  assetUsdt: "USDT TRC20",
  assetCustom: "Другой TRC20",
  amountTrx: "Сумма (TRX)",
  amountToken: "Сумма (токен)",
  contractAddress: "Адрес контракта",
  decimals: "Десятичные знаки",
  decimalsLocked: "Десятичные (заблокировано)",
  nextReview: "Далее: Проверка",
  invalidAddress: "Некорректный адрес TRON",
  addressesMustDiffer: "Адреса отправителя и получателя должны различаться",
  amountMustBePositive: "Сумма должна быть больше 0",
  amountTooLarge: "Сумма слишком велика для безопасного преобразования",
  invalidDecimals: "Десятичные знаки должны быть от 0 до 18",
  suspiciousAddress: "Внимание: адрес получателя выглядит подозрительно. Пожалуйста, проверьте ещё раз.",
  invalidUrl: "Некорректный формат URL",
  reviewTitle: "Проверка транзакции",
  reviewNetwork: "Сеть",
  reviewFullHost: "URL ноды",
  reviewAsset: "Актив",
  reviewFrom: "От",
  reviewTo: "Кому",
  reviewAmountTrx: "Сумма (TRX)",
  reviewAmountSun: "Сумма (SUN)",
  reviewAmountToken: "Сумма (токен)",
  reviewSmallestUnit: "Наименьшая единица",
  reviewContract: "Контракт токена",
  reviewDecimals: "Десятичные знаки",
  checkVerifyAddresses: "Я внимательно проверил адреса отправителя и получателя.",
  checkUnderstandFunds: "Я понимаю, что этот файл, после подписания и отправки, может переместить реальные средства.",
  checkCompareOffline: "Я сравню эти данные ещё раз на офлайн-устройстве подписи.",
  exportButton: "Собрать и экспортировать неподписанную TX",
  building: "Сборка…",
  protoDisclaimer: "UI прототип использует моковую сборку; не реальное построение транзакции.",
  doneTitle: "Файл готов",
  doneTxId: "ID транзакции",
  doneNetwork: "Хост сети",
  backToForm: "Назад к форме",
  goHome: "Главная",
  pickFileTitle: "Выберите подписанную транзакцию",
  pickFileButton: "Выбрать подписанный JSON файл",
  pickFileDesc: "Выберите .json файл с подписанной транзакцией.",
  fileInvalidJson: "Файл не содержит корректный JSON.",
  fileMissingTxId: "Отсутствует или пустое поле txID.",
  fileMissingRawData: "Отсутствует объект raw_data.",
  fileMissingRawHex: "Отсутствует или пустое поле raw_data_hex.",
  fileMissingSignature: "Отсутствует или пустой массив подписей.",
  fileInvalidSignatureItem: "Массив подписей содержит пустые элементы.",
  previewTitle: "Предпросмотр транзакции",
  previewTxId: "ID транзакции",
  previewType: "Тип",
  previewFrom: "От",
  previewTo: "Кому",
  previewAmount: "Сумма",
  previewFeeLimit: "Лимит комиссии",
  previewContract: "Контракт токена",
  previewToken: "Токен",
  previewWarnings: "Предупреждения",
  previewDecodeFailed: "Не удалось декодировать данные транзакции для предпросмотра.",
  verifyCheckbox: "Я проверил эту транзакцию на офлайн-устройстве.",
  irreversibleWarning: "Отправка транзакции необратима. После отправки средства не могут быть возвращены.",
  sendButton: "Отправить транзакцию",
  sending: "Отправка…",
  resultSuccessTitle: "Транзакция отправлена",
  resultSuccessTxId: "ID транзакции",
  resultFailTitle: "Не удалось отправить",
  technicalDetails: "Технические детали",
  notFoundTitle: "Страница не найдена",
  notFoundDesc: "Запрашиваемая страница не существует.",
  unknown: "Неизвестно",
  trxTransfer: "Перевод TRX",
  trc20Transfer: "Перевод TRC20",
  sun: "SUN",
};

export type TranslationKey = keyof typeof en;
type Lang = "en" | "ru";

interface I18nContextValue {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: TranslationKey, vars?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

const dicts: Record<Lang, Record<TranslationKey, string>> = { en, ru };

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLang] = useState<Lang>("en");

  const t = useCallback(
    (key: TranslationKey, vars?: Record<string, string | number>) => {
      let str = dicts[lang][key] ?? key;
      if (vars) {
        for (const [k, v] of Object.entries(vars)) {
          str = str.replace(`{${k}}`, String(v));
        }
      }
      return str;
    },
    [lang]
  );

  return (
    <I18nContext.Provider value={{ lang, setLang, t }}>
      {children}
    </I18nContext.Provider>
  );
}

export function useI18n() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used within I18nProvider");
  return ctx;
}
