import yaml, json
def load(request):
    data = yaml.load(request.data, Loader=yaml.SafeLoader)
    obj = json.loads(request.data)
    safe = yaml.safe_load(open("config.yml"))
    return data, obj, safe
