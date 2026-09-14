# rewriters/mongo_rewriter.py
class MongoRewriter:

    def rewrite(self, query: dict, policy: dict, user: dict) -> dict:
        query["filter"] = self._apply_row_filter(query.get("filter", {}), policy, user)
        query["projection"] = self._apply_projection(query.get("projection", {}), policy, user)
        return query

    def _apply_row_filter(self, existing_filter, policy, user):
        row_conditions = {}
        for rf in policy.get("row_filters", []):
            val = rf["value"].replace("{user.region}", user.get("region", ""))
            row_conditions[rf["column"]] = val

        if not row_conditions:
            return existing_filter
        if existing_filter:
            return {"$and": [existing_filter, row_conditions]}
        return row_conditions

    def _apply_projection(self, projection, policy, user):
        col_policies = policy.get("columns", {})
        result = {}

        for field, include in projection.items():
            if field in col_policies:
                action = col_policies[field]["action"]
                exempt = col_policies[field].get("roles_exempt", [])
                if user["role"] in exempt or action == "allow":
                    result[field] = 1
                elif action == "deny":
                    result[field] = 0   # exclude
                elif action in ("mask", "tokenize"):
                    result[field] = 1   # fetch, transform in app layer
            else:
                result[field] = include
        return result