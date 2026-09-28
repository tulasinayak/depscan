from jinja2.sandbox import SandboxedEnvironment

_env = SandboxedEnvironment(autoescape=True)


def render_custom(source, **values):
    return _env.from_string(source).render(**values)
