from werkzeug.serving import WSGIRequestHandler

from tlstest.webapp import app


class ScriptNameHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        print(', '.join(self.headers.keys()))
        print(', '.join(environ.keys()))
        script_name = environ.get('HTTP_X_SCRIPT_NAME', '')
        if script_name:
            environ['SCRIPT_NAME'] = script_name
            path_info = environ['PATH_INFO']
            if path_info.startswith(script_name):
                environ['PATH_INFO'] = path_info[len(script_name):]

        scheme = environ.get('HTTP_X_SCHEME', '')
        if scheme:
            environ['wsgi.url_scheme'] = scheme
        print('PATH:', self.path)
        print('SCRIPT_NAME:', environ['SCRIPT_NAME'])
        print('PATH_INFO:', environ['PATH_INFO'])
        return environ


app.config['PROPAGATE_EXCEPTIONS'] = True
# app.config['TEMPLATES_AUTO_RELOAD'] = True
# app.config['DEBUG'] = True
# app.run(host='0.0.0.0', port=8081, use_evalex=False,
# request_handler=ScriptNameHandler)
app.run(host='0.0.0.0', port=81, use_evalex=False, debug=True)
# rapp = ReverseProxied(app)
# rapp.app.run(host='0.0.0.0', port=8081)
