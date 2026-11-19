"""AI Navigator: a read-only chat about RedAmon's docs and one project's data (plan §8).

The agent holds the model and the wiki index but no project data: every project read is a
callback to the webapp, which re-authorizes it for the person on each call
(webapp/src/app/api/internal/navigator/tools/[name]/route.ts).
"""
