int myglob = 42;

int myglobal_func(int a, int b)
{
    myglob += a;
    return b + myglob;
}
