def get_agent_public_key(self, agent_id: str, force_refresh: bool = False) -> str:
        """Recupera la chiave pubblica PEM dell'agente dal broker. Se force_refresh è True, ignora la cache."""
        if not force_refresh and agent_id in self._pubkey_cache:
            # Semplice TTL logico: potremmo espanderlo salvando un timestamp, 
            # ma il force_refresh chiamato in caso di errore E2E è più robusto.
            return self._pubkey_cache[agent_id]
        
        resp = self._http.get(
            f"{self.base}/registry/agents/{agent_id}/public-key",
            headers=self._headers(),
        )
        resp.raise_for_status()
        pubkey_pem = resp.json()["public_key_pem"]
        self._pubkey_cache[agent_id] = pubkey_pem
        return pubkey_pem
