import yaml, pickle
def load(request):
    data = yaml.load(request.data)
    obj = pickle.loads(request.data)
    return data, obj
