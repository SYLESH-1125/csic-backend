"""
NLP Agent Stub

Provides query_nlp_agent function for evidence service.
This is a minimal replacement for the removed nlp_agent.py.
"""

async def query_nlp_agent(query: str = "", **kwargs):
    """Stub for NLP queries - use LLM service for real queries."""
    return {
        "success": True,
        "query": query,
        "records": [],
        "message": "Use LLM service for NLP queries"
    }
