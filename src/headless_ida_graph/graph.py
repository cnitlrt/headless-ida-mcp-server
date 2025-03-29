from langchain_core.messages import HumanMessage
from langchain_core.prompts import ChatPromptTemplate,HumanMessagePromptTemplate,SystemMessagePromptTemplate,ChatMessagePromptTemplate
from langgraph.graph import StateGraph
from langchain_openai import ChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_core.runnables import RunnableConfig
from langgraph.prebuilt import create_react_agent


from headless_ida_graph.state import State, InputState
from headless_ida_graph.configuration import Configuration
from headless_ida_graph.utils import logger

async def call_mode(state:InputState,config:RunnableConfig):
    async with MultiServerMCPClient(
        {
            # "ida": {
            #     "url": "http://localhost:8888/sse",
            #     "transport": "sse",
            # }
            "ida": {
                "command": "uv",
                "args": ["run","headless_ida_mcp_server"],
                "transport": "stdio",
            },
        }
    ) as client:
        configuration = Configuration().from_runnable_config(config)
        model = ChatOpenAI(model=configuration.model)
        agent = create_react_agent(model, client.get_tools())
        logger.info(str(state.messages))
        res = await agent.ainvoke({"messages":state.messages})
        logger.info(str(res["messages"][-1].content))
        return {"messages":res["messages"][-1]}



builder = StateGraph(State,input=InputState,config_schema=Configuration)
builder.add_node("call_mode",call_mode)
builder.add_edge("__start__","call_mode")

graph = builder.compile()