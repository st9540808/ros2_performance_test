from setuptools import setup

package_name = 'rclpy_demo'

setup(
    name=package_name,
    version='0.0.0',
    packages=[package_name],
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='st9540808',
    maintainer_email='st9540808@gmail.com',
    description='TODO: Package description',
    license='TODO: License declaration',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'talker = rclpy_demo.publisher_member_function:main',
            'listener = rclpy_demo.subscriber_member_function:main',
            'listener_composed = rclpy_demo.subscriber_member_function_composed:main',
        ],
    },
)
