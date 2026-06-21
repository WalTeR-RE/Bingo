import logging as _logging
from pathlib import Path

_logging.getLogger("faiss").setLevel(_logging.WARNING)
_logging.getLogger("faiss.loader").setLevel(_logging.WARNING)

import yaml
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

from ..utils.logger import get_logger

logger = get_logger("rag")


class RAGEngine:
    def __init__(self, config):
        self.config = config
        self.embeddings = OpenAIEmbeddings(
            model=config.models.embeddings,
            openai_api_key=config.openai_api_key,
        )
        self.vector_store: FAISS | None = None
        self.bm25 = None
        self._faiss_path = Path(config.paths.chroma_db).parent / "faiss_index"
        self._init_store()
        self._init_bm25()

    def _init_store(self):
        faiss_dir = str(self._faiss_path)
        if self._faiss_path.exists():
            try:
                self.vector_store = FAISS.load_local(
                    faiss_dir,
                    self.embeddings,
                    allow_dangerous_deserialization=True,
                )
                logger.info("Loaded existing FAISS index from %s", faiss_dir)
            except Exception as e:
                logger.warning("Could not load FAISS index: %s", e)
                self.vector_store = None
        else:
            self.vector_store = None

    def _init_bm25(self):
        self.bm25 = None
        try:
            from langchain_community.retrievers import BM25Retriever

            documents = self._load_documents()
            if documents:
                self.bm25 = BM25Retriever.from_documents(documents)
                logger.info("BM25 sparse index built over %d chunks", len(documents))
        except Exception as e:
            logger.warning("BM25 unavailable, falling back to dense-only RAG: %s", e)

    def _splitter(self) -> RecursiveCharacterTextSplitter:
        return RecursiveCharacterTextSplitter(
            chunk_size=1500,
            chunk_overlap=200,
            separators=["\n## ", "\n### ", "\n#### ", "\n\n", "\n"],
        )

    def _load_documents(self, knowledge_base_path: str = None) -> list[Document]:
        kb_path = Path(knowledge_base_path or self.config.paths.knowledge_base)
        if not kb_path.exists():
            logger.error("Knowledge base path does not exist: %s", kb_path)
            return []

        splitter = self._splitter()
        documents: list[Document] = []
        for md_file in kb_path.rglob("*.md"):
            try:
                text = md_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as e:
                logger.warning("Skipping unreadable KB file %s: %s", md_file.name, e)
                continue
            metadata = self._extract_metadata(text, md_file)
            for i, chunk in enumerate(splitter.split_text(text)):
                documents.append(
                    Document(page_content=chunk, metadata={**metadata, "chunk_index": i})
                )
        return documents

    def ingest(self, knowledge_base_path: str = None) -> int:
        documents = self._load_documents(knowledge_base_path)
        if documents:
            if self.vector_store is None:
                self.vector_store = FAISS.from_documents(documents, self.embeddings)
            else:
                self.vector_store.add_documents(documents)
            self.vector_store.save_local(str(self._faiss_path))
            self._init_bm25()
            logger.info("Ingested %d chunks from %s", len(documents),
                        knowledge_base_path or self.config.paths.knowledge_base)
        return len(documents)

    @staticmethod
    def _retrieve(retriever, question: str) -> list[Document]:
        try:
            return retriever.invoke(question)
        except Exception:
            try:
                return retriever.get_relevant_documents(question)
            except Exception:
                return []

    def query(
        self,
        question: str,
        vuln_type: str = None,
        tool_name: str = None,
        top_k: int = 5,
    ) -> list[Document]:
        pool = max(top_k * 3, 12)
        fused: dict[str, list] = {}

        def _fuse(docs, weight):
            for rank, doc in enumerate(docs):
                key = doc.page_content[:300]
                score = weight * (1.0 / (rank + 60))
                if key in fused:
                    fused[key][1] += score
                else:
                    fused[key] = [doc, score]

        if self.vector_store is not None:
            try:
                _fuse(self.vector_store.similarity_search(question, k=pool), 0.6)
            except Exception as e:
                logger.warning("Dense retrieval failed: %s", e)

        if self.bm25 is not None:
            try:
                self.bm25.k = pool
            except Exception:
                pass
            _fuse(self._retrieve(self.bm25, question), 0.4)

        if not fused:
            return []

        vt = (vuln_type or "").lower()
        tn = (tool_name or "").lower()

        def _final(item):
            doc, score = item
            meta = doc.metadata or {}
            hay = " ".join(str(meta.get(k, "")) for k in ("vuln_type", "tool_name", "filename", "source")).lower()
            if vt and vt in hay:
                score += 0.5
            if tn and tn in hay:
                score += 0.5
            return score

        ordered = sorted(fused.values(), key=_final, reverse=True)
        return [doc for doc, _ in ordered[:top_k]]

    def get_context(self, question: str, vuln_type: str = None, top_k: int = 5) -> str:
        docs = self.query(question, vuln_type=vuln_type, top_k=top_k)
        if not docs:
            return "No relevant knowledge found."
        return "\n\n---\n\n".join(d.page_content for d in docs)

    def get_retriever(self, vuln_type: str = None, top_k: int = 5):
        if not self.vector_store:
            return None
        return self.vector_store.as_retriever(search_kwargs={"k": top_k})

    @staticmethod
    def _extract_metadata(text: str, filepath: Path) -> dict:
        metadata = {
            "source": str(filepath),
            "filename": filepath.name,
            "category": filepath.parent.name,
        }
        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) >= 3:
                try:
                    fm = yaml.safe_load(parts[1])
                    if isinstance(fm, dict):
                        for key in ["vuln_type", "tool_name", "severity", "category"]:
                            if key in fm:
                                val = fm[key]
                                if isinstance(val, list):
                                    val = val[0] if val else ""
                                metadata[key] = str(val)
                except yaml.YAMLError:
                    pass
        return metadata
