"""Thin MCP protocol adapter; business behavior lives in the domain layer."""

from mcp.server.fastmcp import FastMCP

from ti_mcp.config import Settings, configure_logging
from ti_mcp.connectors.otx import OTXConnector
from ti_mcp.domain.analysis import AnalysisService
from ti_mcp.domain.models import Report, ToolErrorDetail, ToolErrorResponse
from ti_mcp.domain.validation import IndicatorValidationError


def create_server(service: AnalysisService) -> FastMCP:
    server = FastMCP("Threat Intelligence")

    @server.tool()
    async def analyze_indicator(value: str) -> Report | ToolErrorResponse:
        """Validate an IOC and return a passive threat-intelligence report."""
        try:
            return await service.analyze(value)
        except IndicatorValidationError as exc:
            return ToolErrorResponse(
                error=ToolErrorDetail(code=exc.code, message=str(exc))
            )

    return server


def main() -> None:
    configure_logging()
    settings = Settings.from_env()
    service = AnalysisService(
        connectors=[OTXConnector(settings)],
        max_indicator_length=settings.max_indicator_length,
    )
    create_server(service).run(transport="stdio")


if __name__ == "__main__":
    main()
