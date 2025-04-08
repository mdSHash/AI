import os
import logging
import threading
import yaml
from dotenv import load_dotenv

from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain.chains import ConversationalRetrievalChain
from langchain.memory import ConversationBufferMemory
from langchain.prompts import PromptTemplate
from langchain_ibm import WatsonxLLM
from ibm_watsonx_ai.foundation_models.utils.enums import DecodingMethods
from ibm_watsonx_ai.metanames import GenTextParamsMetaNames as GenParams

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()
project_id = os.getenv("PROJECT_ID")  # Get project ID for Watsonx
watsonx_url = os.getenv("WATSONX_URL")  # Get Watsonx API URL

# Load configurations
def load_config(config_path="config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

config = load_config()
PERSIST_DIRECTORY = config['persist_directory']
EMBEDDING_MODEL = config.get('embedding_model', "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")

class WatsonxModelSingleton:
    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_model(cls):
        with cls._lock:
            if cls._instance is None:
                try:
                    logger.info("Initializing Watsonx model...")
                    parameters = {
                        GenParams.DECODING_METHOD: DecodingMethods.SAMPLE,
                        GenParams.TEMPERATURE: 0.7,
                        GenParams.TOP_P: 0.3,
                        GenParams.MAX_NEW_TOKENS: 300,
                        GenParams.STOP_SEQUENCES: ["<|endoftext|>"]
                    }
                    
                    # Initialize Watsonx language model
                    cls._instance = WatsonxLLM(
                        model_id="meta-llama/llama-3-1-70b-instruct",  # Using Llama 3 for better multilingual support
                        project_id=project_id,
                        params=parameters,
                        version="2023-05-29"
                    )
                    logger.info("Watsonx model initialized successfully.")
                except Exception as e:
                    logger.error(f"Error initializing Watsonx model: {e}")
                    raise
        return cls._instance

def setup_retrieval_chain():
    # Get the language model
    watsonx_model = WatsonxModelSingleton.get_model()
    
    # Dictionary to store individual user conversation memories
    conversation_memories = {}
    
    # Create a vector database instance
    vector_db = Chroma(
        persist_directory=PERSIST_DIRECTORY,
        embedding_function=SentenceTransformerEmbeddings(model_name=EMBEDDING_MODEL)
    )
    
    # Define a custom prompt template that handles multiple languages
    prompt_template = PromptTemplate(
        input_variables=["context", "question", "chat_history", "user_context"],
        template="""
        You are a helpful educational assistant for a UAE institute. Answer the question based on the provided context.
        Important rules:
        1. ALWAYS respond in the same language as the user's question
        2. If the user is asking about their scores or performance, ONLY provide information from their own student records
        3. For teachers and admins, you can provide broader information about courses and student performance
        4. If you don't know the answer, say so honestly
        5. Keep responses concise and tailored to the user's role

        User information:
        {user_context}

        Previous conversation:
        {chat_history}

        Context from documents:
        {context}

        Question:
        {question}

        Answer:
        """
    )
    
    # Configure the retriever
    retriever = vector_db.as_retriever(search_kwargs={"k": 5})
    
    # Create and return the conversational retrieval chain
    chain = ConversationalRetrievalChain.from_llm(
        llm=watsonx_model,
        retriever=retriever,
        combine_docs_chain_kwargs={"prompt": prompt_template}
    )
    
    return chain, conversation_memories
