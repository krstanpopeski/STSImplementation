public class STSImplementation {

    public static void main(String[] args) {
        User Alice = new User("Allice");
        User Bob = new User("Bob");
        try {
            Alice.sendFirstMessage(Bob);
        }
        catch(Exception e){
            System.err.println(e.getMessage());
        }
    }

}
