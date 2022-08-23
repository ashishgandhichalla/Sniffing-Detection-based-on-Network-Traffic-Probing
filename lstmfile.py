Python 3.6.2 (v3.6.2:5fd33b5, Jul  8 2017, 04:57:36) [MSC v.1900 64 bit (AMD64)] on win32
Type "copyright", "credits" or "license()" for more information.
>>> #Import the libraries
import math
import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from keras.models import Sequential
from keras.layers import Dense, LSTM
import matplotlib.pyplot as plt
plt.style.use('fivethirtyeight')


features = (np.random.randint(10, size=(100, 1)))
print(features.shape)

df = pd.read_csv(r"C:\Users\HP\Desktop\Sniffing Detection Based on Network\sniffing dataset.csv",header=None,names=colnames)

training_dataset_length = math.ceil(len(features) * .75)
print(training_dataset_length)

#Scale the all of the data to be values between 0 and 1 
scaler = MinMaxScaler(feature_range=(0, 1)) 
scaled_data = scaler.fit_transform(features)

splt = (re.findall(r"[\w']+", str(txt)))

    for f in splt:
        if f in ('IPid', 'FDDI', 'x25', 'rangingdistance'):
            attack1.append(f)
        elif f in ('tcpchecksum', 'mtcp', 'controlflags', 'tcpoffset', 'tcpport'):
            attack2.append(f)
        elif f in ('ICMPID', 'udptraffic', 'udpunicorn', 'datagramid', 'NTP', 'RIP', 'TFTP'):
            attack3.append(f)
        elif f in ('GETID', 'POSTID', 'openBSD', 'appid', 'sessionid', 'transid', 'physicalid'):
            attack4.append(f)
        elif f in ('SYN', 'ACK', 'synpacket', 'sycookies'):
            attack5.append(f)
        elif f in ('serverattack', 'serverid', 'blockbankwidth'):
            attack6.append(f)
        elif f in ('monlist', 'getmonlist', 'NTPserver'):
            attack7.append(f)
        elif f in ('portid', 'FTPID', 'tryion', 'fragflag'):
            attack8.append(f)
        elif f in ('malwareid', 'gethttpid', 'httpid'):
            attack9.append(f)

    if len(attack1) > len(attack2) and len(attack1) > len(attack3) and len(attack1) > len(attack4) and len(
            attack1) > len(attack5) and len(attack1) > len(attack6) and len(attack1) > len(attack7) and len(
        attack1) > len(attack8) and len(attack1) > len(attack9):
        ans = "Man-in-the-middle Attack"
    elif len(attack2) > len(attack1) and len(attack2) > len(attack3) and len(attack2) > len(attack4) and len(
            attack2) > len(attack5) and len(attack2) > len(attack6) and len(attack2) > len(attack7) and len(
        attack2) > len(attack8) and len(attack2) > len(attack9):
        ans = "Phishing and spear phishing attacks"
    elif len(attack3) > len(attack2) and len(attack3) > len(attack1) and len(attack3) > len(attack4) and len(
            attack1) > len(attack5) and len(attack1) > len(attack6) and len(attack1) > len(attack7) and len(
        attack1) > len(attack8) and len(attack1) > len(attack9):
        ans = "Drive-by attack"
    elif len(attack4) > len(attack2) and len(attack4) > len(attack3) and len(attack4) > len(attack1) and len(
            attack4) > len(attack5) and len(attack4) > len(attack6) and len(attack4) > len(attack7) and len(
        attack4) > len(attack8) and len(attack4) > len(attack9):
        ans = "Password attack"
    elif len(attack5) > len(attack2) and len(attack5) > len(attack3) and len(attack5) > len(attack4) and len(
            attack5) > len(attack1) and len(attack5) > len(attack6) and len(attack5) > len(attack7) and len(
        attack5) > len(attack8) and len(attack5) > len(attack9):
        ans = "SQL injection attack"
    elif len(attack6) > len(attack2) and len(attack6) > len(attack3) and len(attack6) > len(attack4) and len(
            attack6) > len(attack5) and len(attack6) > len(attack1) and len(attack6) > len(attack7) and len(
        attack6) > len(attack8) and len(attack6) > len(attack9):
        ans = "Cross-site scripting (XSS) attack"
    elif len(attack7) > len(attack2) and len(attack7) > len(attack3) and len(attack7) > len(attack4) and len(
            attack7) > len(attack5) and len(attack7) > len(attack6) and len(attack7) > len(attack1) and len(
        attack7) > len(attack8) and len(attack7) > len(attack9):
        ans = "Eavesdropping attack"
    elif len(attack8) > len(attack2) and len(attack8) > len(attack3) and len(attack8) > len(attack4) and len(
            attack8) > len(attack5) and len(attack8) > len(attack6) and len(attack8) > len(attack7) and len(
        attack8) > len(attack1) and len(attack8) > len(attack9):
        ans = "Birthday attack"
    elif len(attack9) > len(attack2) and len(attack9) > len(attack3) and len(attack9) > len(attack4) and len(
            attack9) > len(attack5) and len(attack9) > len(attack6) and len(attack9) > len(attack7) and len(
        attack9) > len(attack8) and len(attack9) > len(attack1):
        ans = "Teardrop attack"

    else:
        ans = "Unmalware"
    UserAdd_Model.objects.create(uregid=obj,entity=Entity,year=Year,records=Records,organizationtype=Organizationtype,method=Method,adddata=txt,attackresult=ans,time=Time)

return render(request,'users/user_adddata.html')


train_data = scaled_data[0:training_dataset_length  , : ]

#Splitting the data
x_train=[]
y_train = []

for i in range(10, len(train_data)):
    x_train.append(train_data[i-10:i,0])
    y_train.append(train_data[i,0])

#Convert to numpy arrays
x_train, y_train = np.array(x_train), np.array(y_train)

#Reshape the data into 3-D array
x_train = np.reshape(x_train, (x_train.shape[0],x_train.shape[1],1))

----
from keras.layers import Dropout

# Initialising the RNN
model = Sequential()

model.add(LSTM(units = 50, return_sequences = True, input_shape = (x_train.shape[1], 1)))
model.add(Dropout(0.2))

# Adding a second LSTM layer and Dropout layer
model.add(LSTM(units = 50, return_sequences = True))
model.add(Dropout(0.2))

# Adding a third LSTM layer and Dropout layer
model.add(LSTM(units = 50, return_sequences = True))
model.add(Dropout(0.2))

# Adding a fourth LSTM layer and and Dropout layer
model.add(LSTM(units = 50))
model.add(Dropout(0.2))

# Adding the output layer
# For Full connection layer we use dense
# As the output is 1D so we use unit=1
model.add(Dense(units = 1))




#compile and fit the model on 30 epochs
model.compile(optimizer = 'adam', loss = 'mean_squared_error')
model.fit(x_train, y_train, epochs = 30, batch_size = 50)

-----

#Test data set
test_data = scaled_data[training_dataset_length - 10: , : ]

#splitting the x_test and y_test data sets
x_test = []
y_test =  features[training_dataset_length : , : ] 

for i in range(10,len(test_data)):
    x_test.append(test_data[i-10:i,0])
    
#Convert x_test to a numpy array 
x_test = np.array(x_test)

#Reshape the data into 3-D array
x_test = np.reshape(x_test, (x_test.shape[0],x_test.shape[1],1))



#check predicted values
predictions = model.predict(x_test) 
#Undo scaling
predictions = scaler.inverse_transform(predictions)

#Calculate RMSE score
rmse=np.sqrt(np.mean(((predictions- y_test)**2)))
rmse
