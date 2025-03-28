import pytest
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

async def test_ida_function_query():
    model = ChatOpenAI(model="gpt-4")
    
    async with MultiServerMCPClient(
        {
            "ida": {
                "url": "http://localhost:8888/sse",
                "transport": "sse",
            }
        }
    ) as client:
        agent = create_react_agent(model, client.get_tools())
        response = await agent.ainvoke(
            {"messages": HumanMessage(content="get function in 4905")}
        )
        
        assert response is not None
        assert "messages" in response
        assert len(response["messages"]) > 0
        
        content = response["messages"][-1].content
        assert isinstance(content, str)
        assert len(content) > 0

async def test_ida_server_connection():
    async with MultiServerMCPClient(
        {
            "ida": {
                "url": "http://localhost:8888/sse",
                "transport": "sse",
            }
        }
    ) as client:
        assert client is not None
        tools = client.get_tools()
        assert len(tools) > 0
