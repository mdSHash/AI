import logging
from langdetect import detect, LangDetectException
from transformers import MarianMTModel, MarianTokenizer

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Dictionary for language codes
language_map = {
    'ar': 'Arabic',
    'en': 'English',
    'fr': 'French',
    'es': 'Spanish',
    'de': 'German',
    'ru': 'Russian',
    'zh': 'Chinese',
    'hi': 'Hindi',
    'ur': 'Urdu'
}

# Cache for translation models
translation_models = {}
translation_tokenizers = {}

def detect_language(text):
    """Detect the language of the input text."""
    try:
        lang_code = detect(text)
        logger.info(f"Detected language: {language_map.get(lang_code, lang_code)}")
        return lang_code
    except LangDetectException:
        logger.warning("Could not detect language. Defaulting to English.")
        return "en"

def load_translation_model(source_lang, target_lang):
    """Load a translation model for the specified language pair."""
    model_name = f"Helsinki-NLP/opus-mt-{source_lang}-{target_lang}"
    key = f"{source_lang}-{target_lang}"
    
    if key not in translation_models:
        try:
            logger.info(f"Loading translation model: {model_name}")
            tokenizer = MarianTokenizer.from_pretrained(model_name)
            model = MarianMTModel.from_pretrained(model_name)
            
            translation_models[key] = model
            translation_tokenizers[key] = tokenizer
        except Exception as e:
            logger.error(f"Failed to load translation model {model_name}: {e}")
            return None, None
    
    return translation_models[key], translation_tokenizers[key]

def translate_text(text, source_lang, target_lang):
    """Translate text from source language to target language."""
    if source_lang == target_lang:
        return text
    
    model, tokenizer = load_translation_model(source_lang, target_lang)
    if not model or not tokenizer:
        logger.warning(f"Translation from {source_lang} to {target_lang} not available.")
        return text
    
    try:
        inputs = tokenizer(text, return_tensors="pt", padding=True)
        translated = model.generate(**inputs)
        result = tokenizer.batch_decode(translated, skip_special_tokens=True)
        return result[0]
    except Exception as e:
        logger.error(f"Translation error: {e}")
        return text

def translate_text_if_needed(text, source_lang, target_lang):
    """Translate text only if source and target languages differ."""
    if source_lang != target_lang:
        return translate_text(text, source_lang, target_lang)
    return text

def get_supported_language_pairs():
    """Return a list of supported language pairs for translation."""
    # These are commonly supported by Helsinki-NLP models
    return [
        ("en", "ar"),  # English to Arabic
        ("ar", "en"),  # Arabic to English
        ("en", "fr"),  # English to French
        ("fr", "en")   # French to English
    ]
