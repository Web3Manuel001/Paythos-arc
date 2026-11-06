"""Framework adapters (CrewAI, LangChain). Optional dependencies, lazy imports."""

from .crewai import make_crewai_tools
from .langchain import make_langchain_tools

__all__ = ["make_crewai_tools", "make_langchain_tools"]
