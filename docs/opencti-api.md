# OpenCTI API Notes

This note tracks the internal provider boundary used by SPUC:

```text
StixCatalogProvider
├── LocalStixCatalogProvider
└── OpenCtiStixCatalogProvider
```

Minimum provider methods:

- `search_objects(query, types, limit)`
- `get_object_by_id(id)`
- `create_object(payload)`
- `find_similar_objects(payload)`

The UI and business flows should depend on this provider boundary rather than directly branching on local vs OpenCTI details. This keeps concurrent backend/authentication work easier to merge.
