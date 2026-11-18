from datetime import datetime, timezone

from ..core.entities import Kind, crypto_kind
from ..core.links import dork, manual
from ..core.module import Module


class BitcoinAddress(Module):
    name = "btc_address"
    description = "Saldo, movimientos y actividad de una dirección Bitcoin (mempool.space, sin key)"
    consumes = (Kind.CRYPTO,)
    rate = 2
    hosts = ("mempool.space",)

    async def run(self, ctx, node):
        if crypto_kind(node.value) != "bitcoin":
            return
        r = await ctx.http.get(f"https://mempool.space/api/address/{node.value}", ttl=1800)
        if not r.ok:
            return
        chain = r.json().get("chain_stats", {})
        received, spent = chain.get("funded_txo_sum", 0), chain.get("spent_txo_sum", 0)
        node.attrs.update({"red": "bitcoin", "transacciones": chain.get("tx_count", 0),
                           "recibido_btc": round(received / 1e8, 8), "saldo_btc": round((received - spent) / 1e8, 8)})
        txs = await ctx.http.get(f"https://mempool.space/api/address/{node.value}/txs", ttl=1800)
        if txs.ok and (rows := txs.json()):
            times = [t["status"]["block_time"] for t in rows if t.get("status", {}).get("block_time")]
            if times:
                node.attrs["ultima_actividad"] = datetime.fromtimestamp(max(times), timezone.utc).date().isoformat()
        if chain.get("tx_count", 0) >= 1000:
            ctx.graph.note(self.name, f"Dirección con {chain['tx_count']} transacciones",
                           "Volumen alto: puede ser un servicio o intercambio, no una cuenta personal.", "info", node)


class CryptoLinks(Module):
    name = "crypto_links"
    description = "Exploradores de bloques, reportes de estafas y búsquedas de la dirección"
    consumes = (Kind.CRYPTO,)

    async def run(self, ctx, node):
        a, s = node.value, self.name
        chain = crypto_kind(a)
        if chain == "bitcoin":
            manual(ctx, node, s, "Blockchair (Bitcoin)", f"https://blockchair.com/bitcoin/address/{a}", "blockchain")
            manual(ctx, node, s, "mempool.space", f"https://mempool.space/address/{a}", "blockchain")
            manual(ctx, node, s, "OKLink (Bitcoin)", f"https://www.oklink.com/btc/address/{a}", "blockchain")
        else:
            manual(ctx, node, s, "Etherscan", f"https://etherscan.io/address/{a}", "blockchain")
            manual(ctx, node, s, "Blockchair (Ethereum)", f"https://blockchair.com/ethereum/address/{a}", "blockchain")
            manual(ctx, node, s, "Arbiscan", f"https://arbiscan.io/address/{a}", "blockchain")
            manual(ctx, node, s, "BscScan", f"https://bscscan.com/address/{a}", "blockchain")
        manual(ctx, node, s, "Chainabuse: reportes de estafa", f"https://www.chainabuse.com/address/{a}", "reputacion")
        manual(ctx, node, s, "Google: dirección exacta", dork(f'"{a}"'), "buscador")
