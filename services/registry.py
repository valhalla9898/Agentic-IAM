"""Service registry to manage lifecycle of backend scaffolds."""
from typing import List


class ServiceRegistry:
    def __init__(self):
        # lazy import to avoid import cycles
        from .access_policies import AccessPolicyManager
        from .zero_trust import ZeroTrustEngine
        from .agent_trust import AgentTrustService
        from .investigation import InvestigationCenter

        self.access = AccessPolicyManager()
        self.zerotrust = ZeroTrustEngine()
        self.trust = AgentTrustService()
        self.investigation = InvestigationCenter()

    def initialize(self) -> None:
        """Synchronously initialize services (wrap async initializers)."""
        import asyncio

        services = [self.access, self.zerotrust, self.trust, self.investigation]
        for svc in services:
            init_coro = getattr(svc, "initialize", None)
            if init_coro:
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # schedule and continue
                        loop.create_task(init_coro())
                    else:
                        asyncio.run(init_coro())
                except RuntimeError:
                    # fallback if event loop issues
                    asyncio.run(init_coro())

    def shutdown(self) -> None:
        """Synchronously shutdown services (wrap async shutdown)."""
        import asyncio

        services = [self.investigation, self.trust, self.zerotrust, self.access]
        for svc in services:
            shutdown_coro = getattr(svc, "shutdown", None)
            if shutdown_coro:
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(shutdown_coro())
                    else:
                        asyncio.run(shutdown_coro())
                except RuntimeError:
                    asyncio.run(shutdown_coro())

    def list_services(self) -> List[str]:
        return ["access", "zerotrust", "trust", "investigation"]
