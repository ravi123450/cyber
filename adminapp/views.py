from django.shortcuts import render,redirect
from userapp.models import User
from adminapp.models import Dataset
import pandas as pd
from django.contrib import messages
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.tree import DecisionTreeClassifier 
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
import math

# Create your views here.


def index(request):
    t_users = User.objects.all()
    a_users = User.objects.filter(status="Accepted")
    p_users = User.objects.filter(status="Verified")
    context ={
        't_users':len(t_users),
        'a_users':len(a_users),
        'p_users':len(p_users),

    }
    return render(request,'admin/index.html', context)



def all_users(request):
    user = User.objects.filter(status = "Accepted")
    context = {
        'user':user,
    }
    return render(request,'admin/all-users.html',context)



def attacks_analysis(request):
    datasets = Dataset.objects.all()
    data_list = []
    for dataset in datasets:
        df = pd.read_csv(dataset.file)
        protocol_counts = df['Attack Type'].value_counts()
        normal = protocol_counts.get('normal', 0)
        print(normal)
        dos = protocol_counts.get('dos', 0)
        print(dos)
        probe = protocol_counts.get('probe', 0)
        print(probe)
        r2l = protocol_counts.get('r2l', 0)
        print(r2l)
        u2r = protocol_counts.get('u2r', 0)
        print(u2r)

        data_list.append({
            'title': dataset.title,
            'normal': normal,
            'dos': dos,
            'probe': probe,
            'r2l': r2l,
            'u2r': u2r,

        })

    return render(request, 'admin/attacks-analysis.html', {'data_list': data_list})







def upload_dataset(request):
    if request.method == 'POST':
        csv_file = request.FILES.get('file') 
        if csv_file:
            Dataset.objects.all().delete()
            dataset = Dataset(title=csv_file.name, file=csv_file)
            dataset.save()
            return redirect('view_dataset')
    return render(request,'admin/upload-dataset.html')



def view_dataset(request):
    datasets = Dataset.objects.all()
    data_list = []
    
    for dataset in datasets:
        df = pd.read_csv(dataset.file)
        df = df.head(1000)
        data = df.to_html(index=False)
        data_list.append({
            'title': dataset.title,
            'data': data
        })
        dataset.save()
    return render(request,'admin/view-dataset.html',{'data_list': data_list})


def pending_users(request):
    user = User.objects.filter(status = "Verified")
    print(user)
    context = {
        'user':user,
    }
    return render(request,'admin/pending-users.html',context)


def alg1(request):
    dataset = Dataset.objects.first() 
    df = pd.read_csv(dataset.file)
    target_column = "Attack Type"  
    categorical_columns = ['protocol_type', 'service', 'flag']
    df = pd.get_dummies(df, columns=['protocol_type', 'service', 'flag','target'], prefix=['protocol', 'service', 'flag','target'])
    y = df['Attack Type']
    X = df.drop(columns=['Attack Type'])
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    gnb_model = GaussianNB()
    gnb_model.fit(X_train, y_train)
    y_pred = gnb_model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='macro')
    recall = recall_score(y_test, y_pred, average='macro')
    f1 = f1_score(y_test, y_pred, average='macro') 
    request.session['GNB_accuracy'] = accuracy
    metrics_data = {
        'algorithm': 'Gaussian Naive Bayes',
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
    }
    context = {
        'dataset_title': dataset.title,
        'target_column': target_column,
        'metrics_data': metrics_data,
    }
    return render(request, 'admin/algorithm-one.html',context)



def alg2(request):
    return render(request,'admin/algorithm-two.html',{})



def alg3(request):
    return render(request, 'admin/algorithm-three.html', {})




def alg4(request):
    return render(request,'admin/algorithm-four.html',{})



def alg5(request):
    return render(request, 'admin/algorithm-five.html', {})







def graph_analysis(request):
    GNB_accuracy = request.session.get('GNB_accuracy')
    print(GNB_accuracy)
    DecisionTree_accuracy = request.session.get('DecisionTree_accuracy')
    print(DecisionTree_accuracy)
    RandomForest_accuracy = request.session.get('RandomForest_accuracy')
    print(RandomForest_accuracy)
    LogisticRegression_accuracy = request.session.get('LogisticRegression_accuracy')
    print(LogisticRegression_accuracy)
    al5_accuracy = request.session.get('al5_accuracy')
    print(al5_accuracy)

    if GNB_accuracy is None or DecisionTree_accuracy is None or RandomForest_accuracy is None or LogisticRegression_accuracy is None or al5_accuracy is None:
        messages.info(request, "Run all 5 algorithms before going to the graph")
        return redirect('alg1')

    formatted_GNB_accuracy = "{:.2f}".format(math.floor(float(GNB_accuracy) * 100) / 100)
    formatted_DecisionTree_accuracy = "{:.2f}".format(math.floor(float(DecisionTree_accuracy) * 100) / 100)
    formatted_RandomForest_accuracy = "{:.2f}".format(math.floor(float(RandomForest_accuracy) * 100) / 100)
    formatted_LogisticRegression_accuracy = "{:.2f}".format(math.floor(float(LogisticRegression_accuracy) * 100) / 100)
    formatted_al5_accuracy = "{:.2f}".format(math.floor(float(al5_accuracy) * 100) / 100)

    
    context = {
    'GNB_accuracy': formatted_GNB_accuracy,
    'DecisionTree_accuracy': formatted_DecisionTree_accuracy,
    'RandomForest_accuracy': formatted_RandomForest_accuracy,
    'LogisticRegression_accuracy': formatted_LogisticRegression_accuracy,
    'al5_accuracy': formatted_al5_accuracy
    }
    
    return render(request,'admin/graph-analasis.html',context)





def accept_user(request,user_id):
    user = User.objects.get(user_id=user_id)
    user.status = 'Accepted'
    user.save()
    return redirect('pending_users')

def reject_user(request,user_id):
    user = User.objects.get(user_id = user_id)
    user.delete()
    return redirect('pending_users')


def delete_user(request,user_id):
    user = User.objects.get(user_id = user_id)
    user.delete()
    return redirect('all_users')

