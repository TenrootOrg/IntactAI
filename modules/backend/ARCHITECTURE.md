# Backend Architecture

## Module Dependencies

```
┌─────────────────────────────────────────────────────────────────┐
│                          app.py                                  │
│                   (Main Flask Application)                       │
│                                                                   │
│  • Flask app initialization                                      │
│  • CORS configuration                                            │
│  • Blueprint registration                                        │
│  • Health check endpoint                                         │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ imports & registers
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                         routes/                                  │
│                    (Flask Blueprints)                            │
│                                                                   │
│  ┌────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ client_routes  │  │ velociraptor_   │  │ timesketch_     │  │
│  │                │  │ routes          │  │ routes          │  │
│  │ • /api/clients │  │ • /api/veloci-  │  │ • /api/time-    │  │
│  │                │  │   raptor/*      │  │   sketch/*      │  │
│  └────────────────┘  └─────────────────┘  └─────────────────┘  │
│                                                                   │
│  ┌────────────────┐  ┌─────────────────┐                        │
│  │ dashboard_     │  │ system_routes   │                        │
│  │ routes         │  │                 │                        │
│  │ • /api/dash-   │  │ • /api/logs/*   │                        │
│  │   board/*      │  │ • /api/test     │                        │
│  └────────────────┘  └─────────────────┘                        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ imports & uses
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                        services/                                 │
│                     (Business Logic)                             │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ workflow_service.py                                        │ │
│  │ • Automation runs tracking                                 │ │
│  │ • Job state management                                     │ │
│  │ • Log aggregation                                          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ velociraptor_service.py                                    │ │
│  │ • gRPC connection setup                                    │ │
│  │ • Client data retrieval                                    │ │
│  │ • VQL query execution                                      │ │
│  │ • Hunt creation                                            │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ kape_service.py                                            │ │
│  │ • KAPE artifact collection via gRPC                        │ │
│  │ • Flow monitoring & completion tracking                    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ plaso_service.py                                           │ │
│  │ • log2timeline processing                                  │ │
│  │ • Docker container orchestration                           │ │
│  │ • Timeline file generation                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ timesketch_service.py                                      │ │
│  │ • Timesketch import                                        │ │
│  │ • Sketch & timeline creation                               │ │
│  └────────────────────────────────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ imports
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                        config.py                                 │
│                    (Configuration)                               │
│                                                                   │
│  • Artifact definitions                                          │
│  • Container mappings                                            │
│  • Velociraptor settings                                         │
│  • Timesketch configuration                                      │
│  • Plaso configuration                                           │
└─────────────────────────────────────────────────────────────────┘
```

## Request Flow Example: Timesketch Import

```
1. Client Request
   │
   │  POST /api/timesketch/import
   │  {
   │    "flow_id": "F.XX",
   │    "client_id": "C.XX",
   │    "client_name": "DESKTOP-XX",
   │    ...
   │  }
   │
   ▼
2. timesketch_routes.py
   │  • Validates request
   │  • Creates background thread
   │
   ▼
3. Workflow Orchestration (timesketch_workflow)
   │
   ├─► workflow_service.create_automation_run()
   │   • Creates tracking entry
   │   • Initializes logs
   │
   ├─► kape_service.monitor_flow_completion()
   │   │  • Connects to Velociraptor via gRPC
   │   │  • Polls flow status
   │   │  • Updates workflow_service
   │   └─► velociraptor_service.setup_velociraptor_connection()
   │
   ├─► plaso_service.process_with_plaso()
   │   • Launches Docker container
   │   • Processes artifacts with log2timeline
   │   • Streams output to logs
   │
   └─► timesketch_service.import_to_timesketch()
       • Imports timeline to Timesketch
       • Parses sketch/timeline IDs
       • Updates workflow_service
```

## API Endpoints Map

```
┌──────────────────────────────────────────────────────────────┐
│ Client Management (client_routes.py)                         │
├──────────────────────────────────────────────────────────────┤
│ GET  /api/clients              → get_clients_from_snapshot() │
│ GET  /api/client/<id>          → Not implemented             │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Velociraptor Operations (velociraptor_routes.py)             │
├──────────────────────────────────────────────────────────────┤
│ POST /api/velociraptor/timesketch → run_kape_collection()    │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Timesketch Operations (timesketch_routes.py)                 │
├──────────────────────────────────────────────────────────────┤
│ POST /api/timesketch/import    → Full workflow pipeline      │
│ GET  /api/timesketch/status    → Get job status              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Dashboard & Monitoring (dashboard_routes.py)                 │
├──────────────────────────────────────────────────────────────┤
│ GET /api/dashboard/automations → get_all_automation_runs()   │
│ GET /api/dashboard/automation/<id> → get_automation_run()    │
│ GET /api/dashboard/automation/<id>/logs → get run logs       │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ System & Logs (system_routes.py)                             │
├──────────────────────────────────────────────────────────────┤
│ GET    /api/logs/<service>     → Fetch container logs        │
│ DELETE /api/logs/<service>     → Clear container logs        │
│ GET    /api/test               → Test endpoint               │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Health Check (app.py)                                         │
├──────────────────────────────────────────────────────────────┤
│ GET /health                    → Health status               │
└──────────────────────────────────────────────────────────────┘
```

## Service Dependencies

```
velociraptor_service.py
  ↓
  • Uses: config.py (VELOCIRAPTOR_CONTAINER, paths)
  • External: grpc, pyvelociraptor, subprocess

kape_service.py
  ↓
  • Uses: velociraptor_service.setup_velociraptor_connection()
  • External: grpc, pyvelociraptor

plaso_service.py
  ↓
  • Uses: config.py (PLASO_*, VELOCIRAPTOR_CONTAINER)
  • External: subprocess, Docker

timesketch_service.py
  ↓
  • Uses: None (standalone)
  • External: subprocess, timesketch_importer

workflow_service.py
  ↓
  • Uses: None (state management only)
  • External: time, datetime
```

## State Management

```
┌─────────────────────────────────────────────────────────────┐
│                   workflow_service.py                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  jobs = {}                                                   │
│    └─► {                                                     │
│          "flow_id": {                                        │
│            "client_id": "C.XX",                              │
│            "artifact_id": "kape",                            │
│            "status": "collecting|processing|completed",      │
│            "phase": "Current operation description",         │
│            ...                                               │
│          }                                                   │
│        }                                                     │
│                                                              │
│  automation_runs = []                                        │
│    └─► [                                                     │
│          {                                                   │
│            "id": "timesketch_1234567890",                    │
│            "type": "timesketch",                             │
│            "name": "Timesketch Import - DESKTOP-XX",         │
│            "status": "running|completed|failed",             │
│            "progress": 0-100,                                │
│            "logs": [                                         │
│              {                                               │
│                "timestamp": "2024-12-09T...",                │
│                "level": "info|success|error",                │
│                "message": "..."                              │
│              }                                               │
│            ]                                                 │
│          }                                                   │
│        ]                                                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Key Design Patterns

1. **Separation of Concerns**
   - Routes: HTTP handling only
   - Services: Business logic only
   - Config: Configuration only

2. **Blueprint Pattern**
   - Each route module registers a Flask Blueprint
   - Blueprints are registered in main app.py

3. **Service Layer Pattern**
   - All business logic extracted to services
   - Routes call services, never implement logic

4. **Dependency Injection**
   - Services import what they need
   - Config centralized and imported

5. **State Management**
   - Centralized in workflow_service
   - Single source of truth for jobs/runs
